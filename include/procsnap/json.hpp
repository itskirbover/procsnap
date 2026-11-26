#pragma once

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace procsnap::json {

class Value {
public:
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value>;

    Value() : data_(std::monostate{}) {}
    Value(std::nullptr_t) : data_(std::monostate{}) {}
    Value(bool b) : data_(b) {}
    Value(int v) : data_(static_cast<int64_t>(v)) {}
    Value(int64_t v) : data_(v) {}
    Value(uint32_t v) : data_(static_cast<int64_t>(v)) {}
    Value(uint64_t v) : data_(static_cast<int64_t>(v)) {}
    Value(double v) : data_(v) {}
    Value(const char* s) : data_(std::string(s ? s : "")) {}
    Value(std::string s) : data_(std::move(s)) {}
    Value(std::string_view s) : data_(std::string(s)) {}
    Value(Array a) : data_(std::move(a)) {}
    Value(Object o) : data_(std::move(o)) {}

    [[nodiscard]] bool is_null() const { return std::holds_alternative<std::monostate>(data_); }
    [[nodiscard]] bool is_bool() const { return std::holds_alternative<bool>(data_); }
    [[nodiscard]] bool is_int() const { return std::holds_alternative<int64_t>(data_); }
    [[nodiscard]] bool is_double() const { return std::holds_alternative<double>(data_); }
    [[nodiscard]] bool is_number() const { return is_int() || is_double(); }
    [[nodiscard]] bool is_string() const { return std::holds_alternative<std::string>(data_); }
    [[nodiscard]] bool is_array() const { return std::holds_alternative<Array>(data_); }
    [[nodiscard]] bool is_object() const { return std::holds_alternative<Object>(data_); }

    [[nodiscard]] bool as_bool(bool fallback = false) const {
        return is_bool() ? std::get<bool>(data_) : fallback;
    }

    [[nodiscard]] int64_t as_int(int64_t fallback = 0) const {
        if (is_int()) return std::get<int64_t>(data_);
        if (is_double()) return static_cast<int64_t>(std::get<double>(data_));
        return fallback;
    }

    [[nodiscard]] double as_double(double fallback = 0.0) const {
        if (is_double()) return std::get<double>(data_);
        if (is_int()) return static_cast<double>(std::get<int64_t>(data_));
        return fallback;
    }

    [[nodiscard]] const std::string& as_string() const {
        static const std::string kEmpty;
        return is_string() ? std::get<std::string>(data_) : kEmpty;
    }

    [[nodiscard]] const Array& as_array() const {
        static const Array kEmpty;
        return is_array() ? std::get<Array>(data_) : kEmpty;
    }

    [[nodiscard]] Array& as_array_mut() {
        if (!is_array()) data_ = Array{};
        return std::get<Array>(data_);
    }

    [[nodiscard]] const Object& as_object() const {
        static const Object kEmpty;
        return is_object() ? std::get<Object>(data_) : kEmpty;
    }

    [[nodiscard]] Object& as_object_mut() {
        if (!is_object()) data_ = Object{};
        return std::get<Object>(data_);
    }

    [[nodiscard]] bool contains(const std::string& key) const {
        if (!is_object()) return false;
        return std::get<Object>(data_).contains(key);
    }

    [[nodiscard]] const Value& at(const std::string& key) const {
        static const Value kNull;
        if (!is_object()) return kNull;
        const auto& obj = std::get<Object>(data_);
        auto it = obj.find(key);
        return it == obj.end() ? kNull : it->second;
    }

    Value& operator[](const std::string& key) {
        return as_object_mut()[key];
    }

    void push_back(Value v) {
        as_array_mut().push_back(std::move(v));
    }

    [[nodiscard]] std::string dump(int indent = -1) const;

private:
    std::variant<std::monostate, bool, int64_t, double, std::string, Array, Object> data_;
};

class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

Value parse(std::string_view input);
Value parse_file(const std::string& path);

}  // namespace procsnap::json
