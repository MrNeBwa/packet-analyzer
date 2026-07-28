#ifndef THREAD_SAFE_QUEUE_HPP
#define THREAD_SAFE_QUEUE_HPP

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

template <typename T> class ThreadSafeQueue {
public:
  ThreadSafeQueue() = default;
  ~ThreadSafeQueue() = default;

  // Запрет копирования
  ThreadSafeQueue(const ThreadSafeQueue &) = delete;
  ThreadSafeQueue &operator=(const ThreadSafeQueue &) = delete;

  void push(T value) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      queue_.push(std::move(value));
    }
    cv_.notify_one();
  }

  bool pop(T &value) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return !queue_.empty() || stop_flag_; });

    if (queue_.empty() && stop_flag_) {
      return false;
    }

    value = std::move(queue_.front());
    queue_.pop();
    return true;
  }

  void stop() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stop_flag_ = true;
    }
    cv_.notify_all();
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

private:
  std::queue<T> queue_;
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  bool stop_flag_ = false;
};

#endif // THREAD_SAFE_QUEUE_HPP
