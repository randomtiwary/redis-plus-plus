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

#ifndef SEWENEW_REDISPLUSPLUS_JWT_AUTH_H
#define SEWENEW_REDISPLUSPLUS_JWT_AUTH_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sw {

namespace redis {

class ConnectionPool;

/// @brief User-provided callback that returns a JWT (or any password string).
///
/// The library never fetches tokens from the network itself; callers supply
/// whatever logic is needed (HTTP call to an IdP, reading from a secrets
/// manager, a test double that returns a random JWT, etc.).
using TokenFetcher = std::function<std::string()>;

/// @brief Configuration for periodic JWT refresh and gradual re-authentication.
struct JwtAuthOptions {
    /// Required. Invoked by the background refresher (and by `refresh_now()`)
    /// to obtain the latest JWT. Must be thread-safe if the fetcher has state.
    TokenFetcher token_fetcher;

    /// How often the background task calls `token_fetcher`.
    /// Default: 5 minutes. Set to zero only if you rely solely on `refresh_now()`.
    std::chrono::milliseconds refresh_interval{std::chrono::minutes(5)};

    /// Maximum number of idle pooled connections to re-authenticate (or
    /// invalidate, when inline AUTH is disabled) in a single batch.
    /// Keeps credential rotation from dropping the whole pool at once.
    std::size_t reauth_batch_size = 1;

    /// Sleep between successive reauth batches while draining idle connections.
    std::chrono::milliseconds reauth_batch_interval{std::chrono::milliseconds(50)};

    /// When true (default), send AUTH on existing connections with the new JWT
    /// instead of closing them. Connections that fail AUTH are invalidated so
    /// the pool reconnects them lazily with the new password.
    bool prefer_inline_reauth = true;
};

/// @brief Thread-safe holder of the current password (JWT) and a generation id.
///
/// Each successful password update increments `generation()`. Connection pools
/// and connections compare against this value to decide whether they still need
/// to re-authenticate.
class JwtCredentials {
public:
    explicit JwtCredentials(std::string initial_password = {});

    JwtCredentials(const JwtCredentials &) = delete;
    JwtCredentials& operator=(const JwtCredentials &) = delete;

    std::string password() const;

    std::uint64_t generation() const;

    /// Atomically replace the password and bump the generation counter.
    /// Returns the new generation.
    std::uint64_t update(std::string password);

    /// Snapshot password and generation under a single lock.
    std::pair<std::string, std::uint64_t> snapshot() const;

private:
    mutable std::mutex _mutex;
    std::string _password;
    std::uint64_t _generation = 0;
};

/// @brief Periodically refreshes a JWT via a user callback and applies it to
/// registered connection pools without dropping all connections at once.
///
/// Typical usage:
/// @code
/// auto creds = std::make_shared<JwtCredentials>(fetch_jwt());
/// JwtAuthOptions jwt_opts;
/// jwt_opts.token_fetcher = fetch_jwt;
/// jwt_opts.refresh_interval = std::chrono::minutes(4);
/// auto manager = std::make_shared<JwtAuthManager>(jwt_opts, creds);
///
/// ConnectionOptions opts;
/// opts.host = "managed-redis.example";
/// opts.password = creds->password(); // initial AUTH uses the JWT as password
///
/// auto pool = std::make_shared<ConnectionPool>(pool_opts, opts);
/// manager->register_pool(pool);
/// manager->start();
/// @endcode
class JwtAuthManager {
public:
    JwtAuthManager(JwtAuthOptions opts, std::shared_ptr<JwtCredentials> credentials);

    /// Convenience: creates credentials from the first successful token fetch.
    explicit JwtAuthManager(JwtAuthOptions opts);

    ~JwtAuthManager();

    JwtAuthManager(const JwtAuthManager &) = delete;
    JwtAuthManager& operator=(const JwtAuthManager &) = delete;

    /// Start the background refresh thread (no-op if already running).
    void start();

    /// Stop the background thread and wait for it to exit.
    void stop();

    /// Whether the background refresher is running.
    bool running() const;

    /// Synchronously call `token_fetcher`, update credentials, and gradually
    /// re-authenticate idle connections on all registered pools.
    /// Thread-safe; may be called while the background thread is running.
    void refresh_now();

    std::shared_ptr<JwtCredentials> credentials() const;

    const JwtAuthOptions& options() const {
        return _opts;
    }

    /// Register a connection pool so it receives password updates and gradual
    /// reauth. Pools are held weakly and cleaned up automatically.
    void register_pool(const std::shared_ptr<ConnectionPool> &pool);

    /// Number of successful token fetches (background + `refresh_now`).
    std::size_t refresh_count() const;

    /// Number of currently registered (still-alive) pools. Intended for tests.
    std::size_t registered_pool_count() const;

private:
    void _run();
    void _apply_to_pools();
    std::vector<std::shared_ptr<ConnectionPool>> _alive_pools();

    JwtAuthOptions _opts;
    std::shared_ptr<JwtCredentials> _credentials;

    std::thread _thread;
    std::atomic<bool> _stop{true};
    std::atomic<bool> _started{false};

    mutable std::mutex _pools_mutex;
    std::vector<std::weak_ptr<ConnectionPool>> _pools;

    std::atomic<std::size_t> _refresh_count{0};

    std::mutex _cv_mutex;
    std::condition_variable _cv;

    // Serialize refresh_now / background refresh so we do not interleave updates.
    std::mutex _refresh_mutex;
};

}

}

#endif // end SEWENEW_REDISPLUSPLUS_JWT_AUTH_H
