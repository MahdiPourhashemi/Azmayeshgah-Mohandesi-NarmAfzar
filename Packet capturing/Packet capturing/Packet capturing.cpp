#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <conio.h>
#include <pcap.h>

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace {

constexpr int kSnapshotLength = 65535;
constexpr int kCaptureTimeoutMs = 100;
constexpr int kCaptureBufferBytes = 4 * 1024 * 1024;
constexpr int kPacketsPerBatch = 64;

struct CaptureDevice {
    std::string name;
    std::string description;
};

struct PacketSummary {
    char source[48]{};
    char destination[48]{};
    char protocol[32]{"Unknown"};
    bool isIPv6{};
    bool hasPorts{};
    std::uint16_t sourcePort{};
    std::uint16_t destinationPort{};
};

struct CaptureOutput {
    std::string text;
    std::size_t packetCount{};
    bool wideLayout{};
};

std::uint16_t readBigEndian16(const u_char* bytes) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[0]) << 8) |
        static_cast<std::uint16_t>(bytes[1]));
}

void formatMacAddress(const u_char* bytes, char* output, std::size_t outputSize) {
    std::snprintf(output, outputSize, "%02x:%02x:%02x:%02x:%02x:%02x",
        static_cast<unsigned int>(bytes[0]), static_cast<unsigned int>(bytes[1]),
        static_cast<unsigned int>(bytes[2]), static_cast<unsigned int>(bytes[3]),
        static_cast<unsigned int>(bytes[4]), static_cast<unsigned int>(bytes[5]));
}

void formatIPv4Address(const u_char* bytes, char* output, std::size_t outputSize) {
    std::snprintf(output, outputSize, "%u.%u.%u.%u",
        static_cast<unsigned int>(bytes[0]), static_cast<unsigned int>(bytes[1]),
        static_cast<unsigned int>(bytes[2]), static_cast<unsigned int>(bytes[3]));
}

void formatIPv6Address(const u_char* bytes, char* output, std::size_t outputSize) {
    std::array<std::uint16_t, 8> groups{};
    for (std::size_t i = 0; i < groups.size(); ++i) {
        groups[i] = readBigEndian16(bytes + i * 2);
    }

    // Compress the longest run of at least two zero groups (RFC 5952 style).
    std::size_t bestStart = groups.size();
    std::size_t bestLength = 1;
    for (std::size_t i = 0; i < groups.size();) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        while (i < groups.size() && groups[i] == 0) ++i;
        if (i - start > bestLength) {
            bestStart = start;
            bestLength = i - start;
        }
    }

    char* cursor = output;
    char* const end = output + outputSize - 1;
    for (std::size_t i = 0; i < groups.size();) {
        if (i == bestStart) {
            if (cursor + 2 > end) break;
            *cursor++ = ':';
            *cursor++ = ':';
            i += bestLength;
            if (i == groups.size()) break;
            continue;
        }

        if (cursor != output && cursor[-1] != ':') {
            if (cursor == end) break;
            *cursor++ = ':';
        }
        const auto converted = std::to_chars(cursor, end, groups[i], 16);
        if (converted.ec != std::errc{}) break;
        cursor = converted.ptr;
        ++i;
    }
    *cursor = '\0';
}

void setTransportPorts(PacketSummary& summary, const u_char* packet,
                       std::size_t offset, std::size_t capturedLength,
                       std::size_t minimumHeaderLength) {
    if (capturedLength >= offset + minimumHeaderLength) {
        summary.sourcePort = readBigEndian16(packet + offset);
        summary.destinationPort = readBigEndian16(packet + offset + 2);
        summary.hasPorts = true;
    }
}

PacketSummary decodePacket(const u_char* packet, std::size_t capturedLength) {
    PacketSummary summary{};
    std::snprintf(summary.protocol, sizeof(summary.protocol), "Unknown");

    if (capturedLength < 14) {
        std::snprintf(summary.protocol, sizeof(summary.protocol), "Short Ethernet");
        return summary;
    }

    formatMacAddress(packet + 6, summary.source, sizeof(summary.source));
    formatMacAddress(packet, summary.destination, sizeof(summary.destination));

    std::size_t networkOffset = 14;
    std::uint16_t etherType = readBigEndian16(packet + 12);
    while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) {
        if (capturedLength < networkOffset + 4) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "Short VLAN");
            return summary;
        }
        etherType = readBigEndian16(packet + networkOffset + 2);
        networkOffset += 4;
    }

    if (etherType == 0x0806) {
        std::snprintf(summary.protocol, sizeof(summary.protocol), "ARP");
        return summary;
    }

    if (etherType == 0x0800) {
        if (capturedLength < networkOffset + 20 || (packet[networkOffset] >> 4) != 4) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "Short IPv4");
            return summary;
        }

        const std::size_t ipHeaderLength = (packet[networkOffset] & 0x0F) * 4;
        if (ipHeaderLength < 20 || capturedLength < networkOffset + ipHeaderLength) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "Invalid IPv4");
            return summary;
        }

        formatIPv4Address(packet + networkOffset + 12, summary.source, sizeof(summary.source));
        formatIPv4Address(packet + networkOffset + 16, summary.destination, sizeof(summary.destination));
        const u_char ipProtocol = packet[networkOffset + 9];
        const std::uint16_t fragment = readBigEndian16(packet + networkOffset + 6);
        const bool firstFragment = (fragment & 0x1FFF) == 0;
        const std::size_t transportOffset = networkOffset + ipHeaderLength;

        if (ipProtocol == 6) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "TCP");
            if (firstFragment) setTransportPorts(summary, packet, transportOffset, capturedLength, 20);
        } else if (ipProtocol == 17) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "UDP");
            if (firstFragment) setTransportPorts(summary, packet, transportOffset, capturedLength, 8);
        } else if (ipProtocol == 1) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "ICMP");
        } else {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "IPv4(%u)",
                          static_cast<unsigned int>(ipProtocol));
        }
        return summary;
    }

    if (etherType == 0x86DD) {
        if (capturedLength < networkOffset + 40 || (packet[networkOffset] >> 4) != 6) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "Short IPv6");
            return summary;
        }

        formatIPv6Address(packet + networkOffset + 8, summary.source, sizeof(summary.source));
        formatIPv6Address(packet + networkOffset + 24, summary.destination, sizeof(summary.destination));
        summary.isIPv6 = true;

        u_char nextHeader = packet[networkOffset + 6];
        std::size_t transportOffset = networkOffset + 40;
        bool firstFragment = true;
        for (int count = 0; count < 8; ++count) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60) {
                if (capturedLength < transportOffset + 2) break;
                const std::size_t extensionLength =
                    (static_cast<std::size_t>(packet[transportOffset + 1]) + 1) * 8;
                if (capturedLength < transportOffset + extensionLength) break;
                nextHeader = packet[transportOffset];
                transportOffset += extensionLength;
            } else if (nextHeader == 44) {
                if (capturedLength < transportOffset + 8) break;
                const std::uint16_t fragment = readBigEndian16(packet + transportOffset + 2);
                firstFragment = (fragment & 0xFFF8) == 0;
                nextHeader = packet[transportOffset];
                transportOffset += 8;
            } else if (nextHeader == 51) {
                if (capturedLength < transportOffset + 2) break;
                const std::size_t extensionLength =
                    (static_cast<std::size_t>(packet[transportOffset + 1]) + 2) * 4;
                if (capturedLength < transportOffset + extensionLength) break;
                nextHeader = packet[transportOffset];
                transportOffset += extensionLength;
            } else {
                break;
            }
        }

        if (nextHeader == 6) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "TCP");
            if (firstFragment) setTransportPorts(summary, packet, transportOffset, capturedLength, 20);
        } else if (nextHeader == 17) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "UDP");
            if (firstFragment) setTransportPorts(summary, packet, transportOffset, capturedLength, 8);
        } else if (nextHeader == 58) {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "ICMPv6");
        } else {
            std::snprintf(summary.protocol, sizeof(summary.protocol), "IPv6(%u)",
                          static_cast<unsigned int>(nextHeader));
        }
        return summary;
    }

    std::snprintf(summary.protocol, sizeof(summary.protocol), "Eth 0x%04X",
                  static_cast<unsigned int>(etherType));
    return summary;
}

void formatTimestamp(const timeval& timestamp, char* output, std::size_t outputSize) {
    static std::time_t cachedSeconds = static_cast<std::time_t>(-1);
    static std::tm cachedLocalTime{};
    const std::time_t seconds = timestamp.tv_sec;
    if (seconds != cachedSeconds) {
        if (localtime_s(&cachedLocalTime, &seconds) == 0) {
            cachedSeconds = seconds;
        } else {
            std::snprintf(output, outputSize, "??:??:??.???");
            return;
        }
    }
    std::snprintf(output, outputSize, "%02d:%02d:%02d.%03d",
        cachedLocalTime.tm_hour, cachedLocalTime.tm_min, cachedLocalTime.tm_sec,
        static_cast<int>(timestamp.tv_usec / 1000));
}

void formatEndpoint(const PacketSummary& summary, bool source,
                    char* output, std::size_t outputSize) {
    const char* address = source ? summary.source : summary.destination;
    const std::uint16_t port = source ? summary.sourcePort : summary.destinationPort;
    if (!summary.hasPorts) {
        std::snprintf(output, outputSize, "%s", address);
    } else if (summary.isIPv6) {
        std::snprintf(output, outputSize, "[%s]:%u", address,
                      static_cast<unsigned int>(port));
    } else {
        std::snprintf(output, outputSize, "%s:%u", address,
                      static_cast<unsigned int>(port));
    }
}

void capturePacket(u_char* userData, const pcap_pkthdr* header, const u_char* packet) {
    auto& output = *reinterpret_cast<CaptureOutput*>(userData);
    const PacketSummary summary = decodePacket(packet, header->caplen);
    char timestamp[16]{};
    char source[64]{};
    char destination[64]{};
    char line[256]{};
    formatTimestamp(header->ts, timestamp, sizeof(timestamp));
    formatEndpoint(summary, true, source, sizeof(source));
    formatEndpoint(summary, false, destination, sizeof(destination));

    int length = 0;
    if (output.wideLayout) {
        length = std::snprintf(line, sizeof(line), "%-12s | %6u | %-8s | %-48s | %s\n",
            timestamp, static_cast<unsigned int>(header->len), summary.protocol,
            source, destination);
    } else if (std::strlen(source) <= 22 && std::strlen(destination) <= 22) {
        length = std::snprintf(line, sizeof(line), "%-12s | %5u | %-6s | %-22s | %s\n",
            timestamp, static_cast<unsigned int>(header->len), summary.protocol,
            source, destination);
    } else {
        length = std::snprintf(line, sizeof(line), "%-12s | %5u | %-6s | %s\n",
            timestamp, static_cast<unsigned int>(header->len), summary.protocol,
            source);
        if (length > 0 && static_cast<std::size_t>(length) < sizeof(line)) {
            const int continuationLength = std::snprintf(line + length, sizeof(line) - length,
                "%29s-> %s\n", "", destination);
            if (continuationLength > 0) length += continuationLength;
        }
    }
    if (length > 0) {
        output.text.append(line, static_cast<std::size_t>(length));
        ++output.packetCount;
    }
}

void printCaptureDevices(const std::vector<CaptureDevice>& devices) {
    std::cout << "Packet Capturing - local interface analyzer\n"
              << "Choose an interface you own or are authorized to inspect.\n\n";
    for (std::size_t i = 0; i < devices.size(); ++i) {
        std::cout << (i + 1) << ". " << devices[i].description
                  << "\n   " << devices[i].name << '\n';
    }
}

int getConsoleWidth() {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    const HANDLE outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (outputHandle != INVALID_HANDLE_VALUE &&
        GetConsoleScreenBufferInfo(outputHandle, &info)) {
        return static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1);
    }
    return 80;
}

} // namespace

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    char errorBuffer[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* rawDevices = nullptr;
    if (pcap_findalldevs(&rawDevices, errorBuffer) == -1) {
        std::cerr << "Could not list capture interfaces: " << errorBuffer << '\n';
        return 1;
    }

    std::vector<CaptureDevice> devices;
    for (const pcap_if_t* device = rawDevices; device != nullptr; device = device->next) {
        if (device->name != nullptr) {
            devices.push_back({device->name,
                device->description != nullptr ? device->description : "(no description)"});
        }
    }
    pcap_freealldevs(rawDevices);

    if (devices.empty()) {
        std::cerr << "No capture interfaces found. Check that Npcap is installed.\n";
        return 1;
    }

    printCaptureDevices(devices);
    std::cout << "\nInterface number: ";
    std::size_t selected{};
    if (!(std::cin >> selected) || selected == 0 || selected > devices.size()) {
        std::cerr << "Invalid interface number.\n";
        return 1;
    }
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

    std::cout << "Capture filter (BPF syntax; leave blank for all visible packets): ";
    std::string filterText;
    std::getline(std::cin, filterText);

    pcap_t* capture = pcap_create(devices[selected - 1].name.c_str(), errorBuffer);
    if (capture == nullptr) {
        std::cerr << "Could not create capture handle: " << errorBuffer << '\n';
        return 1;
    }

    const auto setOption = [&](int result, const char* optionName) {
        if (result == 0) return true;
        std::cerr << "Could not set " << optionName << ": " << pcap_geterr(capture) << '\n';
        return false;
    };

    if (!setOption(pcap_set_snaplen(capture, kSnapshotLength), "snapshot length") ||
        !setOption(pcap_set_promisc(capture, 0), "promiscuous mode") ||
        !setOption(pcap_set_timeout(capture, kCaptureTimeoutMs), "capture timeout")) {
        pcap_close(capture);
        return 1;
    }

    // A larger driver buffer helps absorb short bursts while this process prints batches.
    if (pcap_set_buffer_size(capture, kCaptureBufferBytes) != 0) {
        std::cerr << "Warning: using Npcap's default capture buffer: "
                  << pcap_geterr(capture) << '\n';
    }

    const int activationResult = pcap_activate(capture);
    if (activationResult < 0) {
        std::cerr << "Could not activate interface: " << pcap_geterr(capture) << '\n';
        pcap_close(capture);
        return 1;
    }
    if (activationResult > 0) {
        std::cerr << "Capture warning: " << pcap_statustostr(activationResult) << '\n';
    }

    if (pcap_datalink(capture) != DLT_EN10MB) {
        std::cerr << "This version decodes Ethernet interfaces only.\n";
        pcap_close(capture);
        return 1;
    }

    if (!filterText.empty()) {
        bpf_program filter{};
        if (pcap_compile(capture, &filter, filterText.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Invalid capture filter: " << pcap_geterr(capture) << '\n';
            pcap_close(capture);
            return 1;
        }
        if (pcap_setfilter(capture, &filter) == -1) {
            std::cerr << "Could not apply capture filter: " << pcap_geterr(capture) << '\n';
            pcap_freecode(&filter);
            pcap_close(capture);
            return 1;
        }
        pcap_freecode(&filter);
    }

    CaptureOutput output;
    output.wideLayout = getConsoleWidth() >= 138;
    output.text.reserve(kPacketsPerBatch * 256);
    std::cout << "\nCapturing on " << devices[selected - 1].description
              << " (promiscuous mode off). Press Q to stop.\n\n";
    char header[160]{};
    if (output.wideLayout) {
        std::snprintf(header, sizeof(header), "%-12s | %6s | %-8s | %-48s | %s",
                      "Time", "Len", "Proto", "Source", "Destination");
        std::cout << header << '\n' << std::string(134, '-') << '\n';
    } else {
        std::snprintf(header, sizeof(header), "%-12s | %5s | %-6s | %-22s | %s",
                      "Time", "Len", "Proto", "Source", "Destination");
        std::cout << header << '\n' << std::string(79, '-') << '\n';
    }
    std::size_t totalDisplayed = 0;
    bool captureError = false;
    while (true) {
        if (_kbhit()) {
            int key = _getch();
            if (key == 0 || key == 224) key = _getch(); // Consume extended-key scan code.
            if (key == 'q' || key == 'Q') break;
        }

        output.text.clear();
        output.packetCount = 0;
        const int result = pcap_dispatch(capture, kPacketsPerBatch, capturePacket,
                                         reinterpret_cast<u_char*>(&output));
        if (result == PCAP_ERROR) {
            std::cerr << "Capture error: " << pcap_geterr(capture) << '\n';
            captureError = true;
            break;
        }
        if (result == PCAP_ERROR_BREAK) break;

        totalDisplayed += output.packetCount;
        if (!output.text.empty()) {
            std::cout.write(output.text.data(), static_cast<std::streamsize>(output.text.size()));
            std::cout.flush();
        }
    }

    pcap_stat statistics{};
    if (pcap_stats(capture, &statistics) == 0) {
        std::cout << "\nCapture stats: displayed=" << totalDisplayed
                  << ", received=" << statistics.ps_recv
                  << ", kernel drops=" << statistics.ps_drop << '\n';
    }

    pcap_close(capture);
    std::cout << "Capture stopped.\n";
    return captureError ? 1 : 0;
}
