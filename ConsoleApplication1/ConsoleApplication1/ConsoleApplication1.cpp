#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <ctime>


int main() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));

    char a_sort{};
    std::cin >> a_sort;

    if (a_sort == 'a' || a_sort == 'b') {
        int arr[10];

        for (int i = 0; i < 10; ++i) {
            arr[i] = std::rand() % 100;
        }

        if (a_sort == 'a') {
            std::sort(arr, arr + 10);
        }
        else {
            std::sort(arr, arr + 10, std::greater<int>{}); 
        }

        int unique_count = 0;
        for (int i = 0; i < 10; ++i) {
            if (unique_count == 0 || arr[i] != arr[unique_count - 1]) {
                arr[unique_count++] = arr[i];
            }
        }

        std::cout << "\nDistinct sorted numbers:\n";
        for (int i = 0; i < unique_count; ++i) {
            std::cout << arr[i] << ' ';
        }
        std::cout << '\n';
    }
    else {
        std::cout << "Enter 'a' or 'b'.\n";
    }



    //std::cout << "All sorted numbers (including repeats):\n";
    //for (int i = 0; i < 10; ++i) {
    //    std::cout << arr[i] << ' ';
    //}

}