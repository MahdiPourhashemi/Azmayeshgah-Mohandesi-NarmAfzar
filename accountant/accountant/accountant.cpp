#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

struct Item {
    std::size_t counter;
    std::string date;
    std::string title;
    std::int64_t moneyInCents;
};

std::string currentDate() {
    const std::time_t now = std::time(nullptr);
    std::tm localTime{};
    if (localtime_s(&localTime, &now) != 0) {
        return "Unknown";
    }

    char date[11]{};
    std::strftime(date, sizeof(date), "%Y-%m-%d", &localTime);
    return date;
}

std::string formatMoney(std::int64_t moneyInCents) {
    const bool isNegative = moneyInCents < 0;
    const std::uint64_t magnitude = isNegative
        ? static_cast<std::uint64_t>(-(moneyInCents + 1)) + 1
        : static_cast<std::uint64_t>(moneyInCents);

    std::string result = isNegative ? "-" : "";
    result += std::to_string(magnitude / 100);
    result += '.';
    const std::uint64_t cents = magnitude % 100;
    if (cents < 10) result += '0';
    result += std::to_string(cents);
    return result;
}

bool parseMoney(std::string_view text, std::int64_t& moneyInCents) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
    }
    if (text.empty()) return false;

    bool isNegative = false;
    if (text.front() == '-' || text.front() == '+') {
        isNegative = text.front() == '-';
        text.remove_prefix(1);
        if (text.empty()) return false;
    }

    constexpr std::uint64_t maxCents =
        static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    constexpr std::uint64_t maxWhole = maxCents / 100;

    std::uint64_t whole = 0;
    std::size_t wholeDigits = 0;
    while (!text.empty() && text.front() >= '0' && text.front() <= '9') {
        const unsigned digit = static_cast<unsigned>(text.front() - '0');
        if (whole > (maxWhole - digit) / 10) return false;
        whole = whole * 10 + digit;
        text.remove_prefix(1);
        ++wholeDigits;
    }

    std::uint64_t fraction = 0;
    std::size_t fractionDigits = 0;
    if (!text.empty() && text.front() == '.') {
        text.remove_prefix(1);
        while (!text.empty() && text.front() >= '0' && text.front() <= '9') {
            if (fractionDigits == 2) return false;
            fraction = fraction * 10 + static_cast<unsigned>(text.front() - '0');
            text.remove_prefix(1);
            ++fractionDigits;
        }
    }

    if (!text.empty() || (wholeDigits == 0 && fractionDigits == 0)) return false;
    if (fractionDigits == 1) fraction *= 10;
    if (whole > maxWhole || whole * 100 > maxCents - fraction) return false;

    const std::uint64_t magnitude = whole * 100 + fraction;
    const std::int64_t signedValue = static_cast<std::int64_t>(magnitude);
    moneyInCents = isNegative ? -signedValue : signedValue;
    return true;
}

struct ConsoleLayout {
    int left{};
    int top{};
    int width{80};
    int height{25};
};

ConsoleLayout getConsoleLayout() {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(console, &info)) {
        return {info.srWindow.Left, info.srWindow.Top,
            static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1),
            static_cast<int>(info.srWindow.Bottom - info.srWindow.Top + 1)};
    }
    return {};
}

void writeAt(const ConsoleLayout& layout, int row, const std::string& text) {
    if (row < 0 || row >= layout.height) return;
    const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    const COORD position{static_cast<SHORT>(layout.left),
                         static_cast<SHORT>(layout.top + row)};
    const std::string clipped = text.substr(0, static_cast<std::size_t>((std::max)(0, layout.width)));
    DWORD written{};
    SetConsoleCursorPosition(console, position);
    if (!clipped.empty()) {
        WriteConsoleA(console, clipped.data(), static_cast<DWORD>(clipped.size()), &written, nullptr);
    }
}

std::string fitCell(std::string value, int width, bool rightAlign = false) {
    if (width <= 0) return {};
    if (static_cast<int>(value.size()) > width) {
        if (width >= 3) value = value.substr(0, static_cast<std::size_t>(width - 3)) + "...";
        else value.resize(static_cast<std::size_t>(width));
    }
    const std::string padding(static_cast<std::size_t>(width - value.size()), ' ');
    return rightAlign ? padding + value : value + padding;
}

std::string tableBorder(int counterWidth, int titleWidth, int moneyWidth) {
    return "+-" + std::string(static_cast<std::size_t>(counterWidth), '-') + "-+-"
        + std::string(10, '-') + "-+-" + std::string(static_cast<std::size_t>(titleWidth), '-')
        + "-+-" + std::string(static_cast<std::size_t>(moneyWidth), '-') + "-+";
}

void renderDashboard(const std::vector<Item>& items, const std::string& status,
                     const std::string& prompt) {
    const ConsoleLayout layout = getConsoleLayout();
    const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    const std::string blank(static_cast<std::size_t>((std::max)(1, layout.width)), ' ');
    for (int row = 0; row < layout.height; ++row) writeAt(layout, row, blank);

    writeAt(layout, 0, "  ACCOUNTANT  |  ITEM REGISTER");
    writeAt(layout, 1, "  Commands: list  add-item  help  quit");

    const int counterWidth = (std::max)(4, static_cast<int>(std::to_string(items.size()).size()));
    constexpr int dateWidth = 10;
    constexpr int moneyWidth = 14;
    const int titleWidth = (std::max)(8, layout.width - counterWidth - dateWidth - moneyWidth - 17);
    const std::string border = tableBorder(counterWidth, titleWidth, moneyWidth);
    writeAt(layout, 3, border);
    writeAt(layout, 4, "| " + fitCell("No.", counterWidth) + " | " + fitCell("Date", dateWidth)
        + " | " + fitCell("Title", titleWidth) + " | " + fitCell("Money", moneyWidth, true) + " |");
    writeAt(layout, 5, border);

    const int dataStart = 6;
    const int dataEnd = (std::max)(dataStart, layout.height - 5);
    const int visibleRows = dataEnd - dataStart;
    const std::size_t firstItem = items.size() > static_cast<std::size_t>(visibleRows)
        ? items.size() - static_cast<std::size_t>(visibleRows) : 0;

    int row = dataStart;
    if (items.empty()) {
        writeAt(layout, row++, "| " + fitCell("", counterWidth) + " | " + fitCell("", dateWidth)
            + " | " + fitCell("No items yet - type add-item below", titleWidth)
            + " | " + fitCell("", moneyWidth) + " |");
    } else {
        for (std::size_t i = firstItem; i < items.size() && row < dataEnd; ++i, ++row) {
            const Item& item = items[i];
            writeAt(layout, row, "| " + fitCell(std::to_string(item.counter), counterWidth)
                + " | " + fitCell(item.date, dateWidth)
                + " | " + fitCell(item.title, titleWidth)
                + " | " + fitCell(formatMoney(item.moneyInCents), moneyWidth, true) + " |");
        }
    }
    writeAt(layout, dataEnd, border);

    const std::string countLine = "  Items: " + std::to_string(items.size())
        + (firstItem > 0 ? "  |  Showing the most recent " + std::to_string(visibleRows) : "");
    writeAt(layout, layout.height - 4, countLine);
    writeAt(layout, layout.height - 3, "  " + status);
    writeAt(layout, layout.height - 2, "  " + prompt);

    // getline uses the terminal's existing line-input mode. Leave its other
    // input flags (including mouse and QuickEdit behavior) untouched.
    CONSOLE_CURSOR_INFO cursorInfo{};
    if (GetConsoleCursorInfo(console, &cursorInfo)) {
        cursorInfo.bVisible = TRUE;
        SetConsoleCursorInfo(console, &cursorInfo);
    }
    const int cursorColumn = (std::min)(layout.width - 1,
        2 + static_cast<int>(prompt.size()));
    SetConsoleCursorPosition(console, {static_cast<SHORT>(layout.left + cursorColumn),
        static_cast<SHORT>(layout.top + layout.height - 2)});
}

bool readAtPrompt(const std::vector<Item>& items, const std::string& status,
                  const std::string& prompt, std::string& value) {
    renderDashboard(items, status, prompt);
    return static_cast<bool>(std::getline(std::cin, value));
}

bool addItem(std::vector<Item>& items, std::string& status) {
    std::string title;
    if (!readAtPrompt(items, status, "Title: ", title)) return false;

    const bool titleIsBlank = std::all_of(title.begin(), title.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    if (titleIsBlank) {
        status = "The title cannot be empty. Item was not added.";
        return true;
    }

    std::string moneyText;
    if (!readAtPrompt(items, status, "Money (e.g. 12.50): ", moneyText)) return false;

    std::int64_t moneyInCents{};
    if (!parseMoney(moneyText, moneyInCents)) {
        status = "Invalid amount. Enter a number with up to two decimal places.";
        return true;
    }

    items.push_back({items.size() + 1, currentDate(), std::move(title), moneyInCents});
    status = "Item added; the list is updated.";
    return true;
}

std::string normalizeCommand(std::string command) {
    command.erase(command.begin(), std::find_if(command.begin(), command.end(), [](unsigned char ch) {
        return std::isspace(ch) == 0;
    }));
    command.erase(std::find_if(command.rbegin(), command.rend(), [](unsigned char ch) {
        return std::isspace(ch) == 0;
    }).base(), command.end());
    std::transform(command.begin(), command.end(), command.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return command;
}

int main() {
    std::vector<Item> items;
    std::string status = "Ready. Add an item or type a command.";

    std::string command;
    while (true) {
        if (!readAtPrompt(items, status, "accountant> ", command)) break;

        command = normalizeCommand(std::move(command));
        if (command == "add-item") {
            if (!addItem(items, status)) break;
        } else if (command == "list") {
            status = "List refreshed.";
        } else if (command == "quit" || command == "exit") {
            break;
        } else if (command == "help") {
            status = "Commands: list | add-item | help | quit";
        } else {
            status = "Unknown command. Type list, add-item, help, or quit.";
        }
    }

    const ConsoleLayout layout = getConsoleLayout();
    writeAt(layout, layout.height - 2, "Goodbye. Press Enter to close.");
    std::string ignored;
    std::getline(std::cin, ignored);
    return 0;
}
