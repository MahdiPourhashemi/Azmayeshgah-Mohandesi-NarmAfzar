#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <random>
#include <vector>
#include <cstdlib>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <limits>

struct Position {
    int x;
    int y;
};

int main() {
    constexpr int width = 50;
    constexpr int height = 25;
    constexpr int boardTop = 2;
    constexpr int pickupRange = 3;
    constexpr int initialStarCount = 10;
    constexpr DWORD stepDelayMs = 120;

    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO screenInfo{};
    GetConsoleScreenBufferInfo(console, &screenInfo);
    const WORD normalAttributes = screenInfo.wAttributes;
    const WORD rangeAttributes = (normalAttributes & 0x000F) |
        BACKGROUND_BLUE | BACKGROUND_INTENSITY;

    CONSOLE_CURSOR_INFO cursorInfo{};
    GetConsoleCursorInfo(console, &cursorInfo);
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(console, &cursorInfo);

    std::mt19937 random{ std::random_device{}() };
    std::uniform_int_distribution<int> randomX{ 0, width - 1 };
    std::uniform_int_distribution<int> randomY{ 0, height - 1 };

    int x = 15;
    int y = 12;

    std::vector<Position> emojis; // Body, from the head toward the tail
    std::vector<Position> stars;

    auto putWideText = [&](int column, int row, const wchar_t* text, DWORD length) {
        COORD position{
            static_cast<SHORT>(column),
            static_cast<SHORT>(row)
        };
        SetConsoleCursorPosition(console, position);

        DWORD written{};
        WriteConsoleW(console, text, length, &written, nullptr);
    };

    auto isInPickupRange = [&](int px, int py) {
        return std::abs(px - x) <= pickupRange &&
               std::abs(py - y) <= pickupRange;
    };

    auto putBoardText = [&](Position position, const wchar_t* text, DWORD length) {
        SetConsoleTextAttribute(console,
            isInPickupRange(position.x, position.y) ? rangeAttributes : normalAttributes);
        putWideText(position.x * 2, position.y + boardTop, text, length);
        SetConsoleTextAttribute(console, normalAttributes);
    };

    auto addStar = [&]() {
        Position star{};
        bool overlaps;

        do {
            star = { randomX(random), randomY(random) };
            overlaps = (star.x == x && star.y == y);

            for (const Position& other : stars) {
                if (other.x == star.x && other.y == star.y) {
                    overlaps = true;
                    break;
                }
            }
            for (const Position& emoji : emojis) {
                if (emoji.x == star.x && emoji.y == star.y) {
                    overlaps = true;
                    break;
                }
            }
        } while (overlaps);

        stars.push_back(star);
    };

    for (int i = 0; i < initialStarCount; ++i) {
        addStar();
    }

    const wchar_t playerEmoji[] = L"\U0001F612";
    const wchar_t starCharacter[] = L"*";
    const wchar_t emptyCell[] = L"  ";
    const wchar_t instructions[] = L"AI is finding the nearest star...";

    bool gameOver = false;

    while (!stars.empty() && !gameOver) {
        // A* prioritizes routes that are close to a star's pickup area.
        // This usually explores far fewer cells than breadth-first search.
        struct SearchNode {
            Position position;
            Position firstStep;
            int distance;
            int estimatedTotal;
        };
        struct LaterNode {
            bool operator()(const SearchNode& left, const SearchNode& right) const {
                if (left.estimatedTotal == right.estimatedTotal) {
                    return left.distance < right.distance;
                }
                return left.estimatedTotal > right.estimatedTotal;
            }
        };

        auto estimateToNearestStarZone = [&](Position position) {
            int bestEstimate = std::numeric_limits<int>::max();
            for (const Position& star : stars) {
                int dx = std::max(0, std::abs(star.x - position.x) - pickupRange);
                int dy = std::max(0, std::abs(star.y - position.y) - pickupRange);
                // Manhattan distance to the nearest cell in the star's
                // pickup square; this never overestimates the route length.
                bestEstimate = std::min(bestEstimate, dx + dy);
            }
            return bestEstimate;
        };

        // Store only body cells and explored path cells. This avoids clearing
        // full map-sized arrays on every AI turn.
        auto cellKey = [&](Position position) {
            return static_cast<std::size_t>(position.y) * width + position.x;
        };

        std::unordered_set<std::size_t> occupied;
        occupied.reserve(emojis.size());
        for (const Position& emoji : emojis) {
            if (emoji.x >= 0 && emoji.x < width && emoji.y >= 0 && emoji.y < height) {
                occupied.insert(cellKey(emoji));
            }
        }

        std::unordered_map<std::size_t, int> bestDistance;
        bestDistance.reserve(256);

        std::priority_queue<SearchNode, std::vector<SearchNode>, LaterNode> openSet;
        Position start{ x, y };
        bestDistance[cellKey(start)] = 0;
        openSet.push({ start, start, 0, estimateToNearestStarZone(start) });
        bool foundPath = false;
        Position nextPosition{ x, y };
        const int moveX[4] = { 0, 0, -1, 1 };
        const int moveY[4] = { -1, 1, 0, 0 };

        while (!openSet.empty()) {
            SearchNode current = openSet.top();
            openSet.pop();

            if (current.distance != bestDistance[cellKey(current.position)]) {
                continue; // Ignore an outdated queue entry.
            }

            // Move at least one step, so growth has a vacated tail cell.
            if (current.distance > 0 &&
                estimateToNearestStarZone(current.position) == 0) {
                nextPosition = current.firstStep;
                foundPath = true;
                break;
            }

            for (int direction = 0; direction < 4; ++direction) {
                Position neighbor{
                    current.position.x + moveX[direction],
                    current.position.y + moveY[direction]
                };

                if (neighbor.x < 0 || neighbor.x >= width ||
                    neighbor.y < 0 || neighbor.y >= height ||
                    occupied.contains(cellKey(neighbor))) {
                    continue;
                }

                const int newDistance = current.distance + 1;
                const std::size_t neighborKey = cellKey(neighbor);
                auto knownDistance = bestDistance.find(neighborKey);
                if (knownDistance != bestDistance.end() &&
                    newDistance >= knownDistance->second) {
                    continue;
                }

                bestDistance[neighborKey] = newDistance;
                Position firstStep = current.distance == 0
                    ? neighbor
                    : current.firstStep;
                const int estimate = estimateToNearestStarZone(neighbor);
                openSet.push({ neighbor, firstStep, newDistance,
                               newDistance + estimate });
            }
        }
        if (!foundPath) {
            gameOver = true;
            break;
        }

        Position oldHead{ x, y };
        Position oldTail = emojis.empty() ? oldHead : emojis.back();
        x = nextPosition.x;
        y = nextPosition.y;

        // Each body segment follows the previous position of the segment ahead.
        for (std::size_t i = emojis.size(); i > 1; --i) {
            emojis[i - 1] = emojis[i - 2];
        }
        if (!emojis.empty()) {
            emojis[0] = oldHead;
        }

        // Collect one star in range per move, keeping the map at no more
        // than the original ten stars (collected stars are not respawned).
        for (std::size_t i = 0; i < stars.size(); ++i) {
            if (isInPickupRange(stars[i].x, stars[i].y)) {
                stars.erase(stars.begin() + i);
                emojis.push_back(oldTail);
                break;
            }
        }

        system("cls");
        SetConsoleTextAttribute(console, normalAttributes);
        putWideText(0, 0, instructions, 33);

        // Highlight the pickup area using the same range rule as collection.
        SetConsoleTextAttribute(console, rangeAttributes);
        const int firstRow = (y - pickupRange < 0) ? 0 : y - pickupRange;
        const int lastRow = (y + pickupRange >= height) ? height - 1 : y + pickupRange;
        const int firstCol = (x - pickupRange < 0) ? 0 : x - pickupRange;
        const int lastCol = (x + pickupRange >= width) ? width - 1 : x + pickupRange;
        for (int row = firstRow; row <= lastRow; ++row) {
            for (int col = firstCol; col <= lastCol; ++col) {
                putWideText(col * 2, row + boardTop, emptyCell, 2);
            }
        }
        SetConsoleTextAttribute(console, normalAttributes);

        for (const Position& star : stars) {
            putBoardText(star, starCharacter, 1);
        }
        for (const Position& emoji : emojis) {
            putBoardText(emoji, playerEmoji, 2);
        }
        putBoardText({ x, y }, playerEmoji, 2);

        Sleep(stepDelayMs);
    }

    system("cls");
    SetConsoleTextAttribute(console, normalAttributes);

    if (stars.empty()) {
        const wchar_t doneMessage[] = L"AI collected all 10 stars! Done.";
        putWideText(0, 0, doneMessage,
            static_cast<DWORD>(sizeof(doneMessage) / sizeof(doneMessage[0]) - 1));
    } else {
        const wchar_t stuckMessage[] = L"AI found no safe route to a star.";
        putWideText(0, 0, stuckMessage,
            static_cast<DWORD>(sizeof(stuckMessage) / sizeof(stuckMessage[0]) - 1));
    }

    cursorInfo.bVisible = TRUE;
    SetConsoleCursorInfo(console, &cursorInfo);
    return 0;
}





