/**************************************************************************
   Copyright (c) 2026 sewenew

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

#include "sw/redis++/jwt_auth.h"
#include "sw/redis++/connection_pool.h"
#include "sw/redis++/errors.h"

#ifdef REDIS_PLUS_PLUS_HAS_ASYNC
#include "sw/redis++/async_connection_pool.h"
#endif

namespace sw {

namespace redis {

JwtCredentials::JwtCredentials(std::string initial_password) :
    _password(std::move(initial_password)),
    _generation(_password.empty() ? 0 : 1) {}

std::string JwtCredentials::password() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _password;
}

std::uint64_t JwtCredentials::generation() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _generation;
}

std::uint64_t JwtCredentials::update(std::string password) {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    _password = std::move(password);
    ++_generation;
    return _generation;
}

std::pair<std::string, std::uint64_t> JwtCredentials::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return {_password, _generation};
}

JwtAuthManager::JwtAuthManager(JwtAuthOptions opts,
        std::shared_ptr<JwtCredentials> credentials) :
            _opts(std::move(opts)),
            _credentials(std::move(credentials)) {
    if (!_opts.token_fetcher) {
        throw Error("JwtAuthOptions::token_fetcher must be set");
    }
    if (!_credentials) {
        throw Error("JwtCredentials must not be null");
    }
    if (_opts.reauth_batch_size == 0) {
        throw Error("JwtAuthOptions::reauth_batch_size must be greater than 0");
    }
}

JwtAuthManager::JwtAuthManager(JwtAuthOptions opts) : _opts(std::move(opts)) {
    if (!_opts.token_fetcher) {
        throw Error("JwtAuthOptions::token_fetcher must be set");
    }
    if (_opts.reauth_batch_size == 0) {
        throw Error("JwtAuthOptions::reauth_batch_size must be greater than 0");
    }

    auto token = _opts.token_fetcher();
    if (token.empty()) {
        throw Error("token_fetcher returned an empty token");
    }
    _credentials = std::make_shared<JwtCredentials>(std::move(token));
    _refresh_count = 1;
}

JwtAuthManager::~JwtAuthManager() {
    try {
        stop();
    } catch (...) {
        // Destructor must not throw.
    }
}

void JwtAuthManager::start() {
    bool expected = false;
    if (!_started.compare_exchange_strong(expected, true)) {
        return;
    }

    _stop = false;
    _thread = std::thread([this] { _run(); });
}

void JwtAuthManager::stop() {
    if (!_started.load()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(_cv_mutex);
        _stop = true;
    }
    _cv.notify_all();

    if (_thread.joinable()) {
        _thread.join();
    }

    _started = false;
}

bool JwtAuthManager::running() const {
    return _started.load() && !_stop.load();
}

void JwtAuthManager::refresh_now() {
    std::lock_guard<std::mutex> refresh_lock(_refresh_mutex);

    auto token = _opts.token_fetcher();
    if (token.empty()) {
        throw Error("token_fetcher returned an empty token");
    }

    _credentials->update(std::move(token));
    ++_refresh_count;

    _apply_to_pools();
}

std::shared_ptr<JwtCredentials> JwtAuthManager::credentials() const {
    return _credentials;
}

void JwtAuthManager::register_pool(const std::shared_ptr<ConnectionPool> &pool) {
    if (!pool) {
        throw Error("cannot register a null ConnectionPool");
    }

    // Seed the pool with the current JWT so new connections AUTH correctly.
    auto snap = _credentials->snapshot();
    pool->update_password(snap.first, snap.second);

    std::lock_guard<std::mutex> lock(_pools_mutex);
    _pools.emplace_back(pool);
}

#ifdef REDIS_PLUS_PLUS_HAS_ASYNC

void JwtAuthManager::register_async_pool(const std::shared_ptr<AsyncConnectionPool> &pool) {
    if (!pool) {
        throw Error("cannot register a null AsyncConnectionPool");
    }

    auto snap = _credentials->snapshot();
    pool->update_password(snap.first, snap.second);

    std::lock_guard<std::mutex> lock(_pools_mutex);
    _async_pools.emplace_back(pool);
}

#endif

std::size_t JwtAuthManager::refresh_count() const {
    return _refresh_count.load();
}

std::size_t JwtAuthManager::registered_pool_count() const {
    std::lock_guard<std::mutex> lock(_pools_mutex);
    std::size_t count = 0;
    for (const auto &weak : _pools) {
        if (!weak.expired()) {
            ++count;
        }
    }
#ifdef REDIS_PLUS_PLUS_HAS_ASYNC
    for (const auto &weak : _async_pools) {
        if (!weak.expired()) {
            ++count;
        }
    }
#endif
    return count;
}

void JwtAuthManager::_run() {
    while (true) {
        {
            std::unique_lock<std::mutex> lock(_cv_mutex);
            if (_opts.refresh_interval > std::chrono::milliseconds(0)) {
                _cv.wait_for(lock, _opts.refresh_interval, [this] { return _stop.load(); });
            } else {
                // No periodic refresh; wait until stop is requested.
                _cv.wait(lock, [this] { return _stop.load(); });
            }
            if (_stop.load()) {
                return;
            }
        }

        try {
            refresh_now();
        } catch (...) {
            // Keep the refresher alive even if a single fetch fails.
            // Callers can observe errors via their own token_fetcher / logging.
        }
    }
}

std::vector<std::shared_ptr<ConnectionPool>> JwtAuthManager::_alive_pools() {
    std::vector<std::shared_ptr<ConnectionPool>> alive;
    std::vector<std::weak_ptr<ConnectionPool>> survivors;

    std::lock_guard<std::mutex> lock(_pools_mutex);
    survivors.reserve(_pools.size());
    for (auto &weak : _pools) {
        if (auto pool = weak.lock()) {
            alive.push_back(std::move(pool));
            survivors.push_back(weak);
        }
    }
    _pools.swap(survivors);
    return alive;
}

#ifdef REDIS_PLUS_PLUS_HAS_ASYNC

std::vector<std::shared_ptr<AsyncConnectionPool>> JwtAuthManager::_alive_async_pools() {
    std::vector<std::shared_ptr<AsyncConnectionPool>> alive;
    std::vector<std::weak_ptr<AsyncConnectionPool>> survivors;

    std::lock_guard<std::mutex> lock(_pools_mutex);
    survivors.reserve(_async_pools.size());
    for (auto &weak : _async_pools) {
        if (auto pool = weak.lock()) {
            alive.push_back(std::move(pool));
            survivors.push_back(weak);
        }
    }
    _async_pools.swap(survivors);
    return alive;
}

#endif

void JwtAuthManager::_apply_to_pools() {
    auto snap = _credentials->snapshot();
    auto pools = _alive_pools();

    for (auto &pool : pools) {
        pool->update_password(snap.first, snap.second);

        // Gradually re-authenticate idle connections so we never invalidate
        // the entire pool in one shot (avoids a thundering herd of reconnects).
        while (true) {
            auto done = pool->reauth_idle_connections(
                    _opts.reauth_batch_size,
                    snap.first,
                    snap.second,
                    _opts.prefer_inline_reauth);
            if (done == 0) {
                break;
            }
            if (_opts.reauth_batch_interval > std::chrono::milliseconds(0)) {
                std::this_thread::sleep_for(_opts.reauth_batch_interval);
            }
        }
    }

#ifdef REDIS_PLUS_PLUS_HAS_ASYNC
    auto async_pools = _alive_async_pools();
    for (auto &pool : async_pools) {
        pool->update_password(snap.first, snap.second);

        while (true) {
            auto done = pool->reauth_idle_connections(
                    _opts.reauth_batch_size,
                    snap.first,
                    snap.second,
                    _opts.prefer_inline_reauth);
            if (done == 0) {
                break;
            }
            if (_opts.reauth_batch_interval > std::chrono::milliseconds(0)) {
                std::this_thread::sleep_for(_opts.reauth_batch_interval);
            }
        }
    }
#endif
}

}

}
