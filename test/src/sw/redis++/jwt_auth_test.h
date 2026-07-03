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

#ifndef SEWENEW_REDISPLUSPLUS_TEST_JWT_AUTH_TEST_H
#define SEWENEW_REDISPLUSPLUS_TEST_JWT_AUTH_TEST_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <sw/redis++/redis++.h>

namespace sw {

namespace redis {

namespace test {

// Offline JWT/reauth coverage. Not parameterized on RedisInstance because it
// exercises connection-pool credential rotation with an in-process fake token
// fetcher and never talks to a server.
class JwtAuthTest {
public:
    explicit JwtAuthTest(const ConnectionOptions &opts = {}) : _opts(opts) {}

    void run();

private:
    void _test_jwt_as_password();

    void _test_credentials();

    void _test_credentials_thread_safety();

    void _test_manager_validation();

    void _test_manager_refresh();

    void _test_register_pool();

    void _test_pool_password_update();

    void _test_connection_helpers();

    void _test_gradual_reauth();

    void _test_manager_applies_to_pools();

    void _test_background_refresh();

    void _test_configurable_options();

    void _test_concurrent_refresh();

    ConnectionOptions _unreachable_opts(const std::string &password = {}) const;

    ConnectionPoolOptions _pool_opts(std::size_t size) const;

    void _seed_idle_connections(ConnectionPool &pool,
                                std::size_t n,
                                const std::string &password,
                                std::uint64_t generation) const;

    std::string _fake_jwt() const;

    TokenFetcher _counting_fetcher(const std::shared_ptr<std::atomic<int>> &counter) const;

    void _expect_error(const std::function<void()> &fn, const std::string &msg) const;

    JwtAuthOptions _base_opts() const;

    ConnectionOptions _opts;
};

}

}

}

#include "jwt_auth_test.hpp"

#endif // end SEWENEW_REDISPLUSPLUS_TEST_JWT_AUTH_TEST_H
