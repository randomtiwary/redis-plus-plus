/**************************************************************************
   Copyright (c) 2017 sewenew

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 *************************************************************************/

#include <iostream>
#include "jwt_auth_test.h"

int main() {
    try {
        std::cout << "Testing JWT auth..." << std::endl;
        sw::redis::test::JwtAuthTest test;
        test.run();
        std::cout << "Pass jwt auth tests" << std::endl;
        return 0;
    } catch (const sw::redis::Error &e) {
        std::cerr << "JWT auth test failed: " << e.what() << std::endl;
        return -1;
    } catch (const std::exception &e) {
        std::cerr << "JWT auth test failed: " << e.what() << std::endl;
        return -1;
    }
}
