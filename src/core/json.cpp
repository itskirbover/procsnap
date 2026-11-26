#include "procsnap/json.hpp"

#include <charconv>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace procsnap::json {

namespace {

void escape_string(const std::string& s, std::string& out) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

void dump_impl(const Value& val, int indent, int depth, std::string& out) {
    if (val.is_null()) {
        out += "null";
    } else if (val.is_bool()) {
        out += val.as_bool() ? "true" : "false";
    } else if (val.is_int()) {
        out += std::to_string(val.as_int());
    } else if (val.is_double()) {
        double d = val.as_double();
        if (std::isnan(d) || std::isinf(d)) {
            out += "null";
        } else {
            std::ostringstream oss;
            oss << d;
            out += oss.str();
        }
    } else if (val.is_string()) {
        escape_string(val.as_string(), out);
    } else if (val.is_array()) {
        const auto& arr = val.as_array();
        if (arr.empty()) {
            out += "[]";
            return;
        }
        out.push_back('[');
        for (size_t i = 0; i < arr.size(); ++i) {
            if (i > 0) out.push_back(',');
            if (indent >= 0) {
                out.push_back('\n');
                out.append(static_cast<size_t>((depth + 1) * indent), ' ');
            }
            dump_impl(arr[i], indent, depth + 1, out);
        }
        if (indent >= 0) {
            out.push_back('\n');
            out.append(static_cast<size_t>(depth * indent), ' ');
        }
        out.push_back(']');
    } else if (val.is_object()) {
        const auto& obj = val.as_object();
        if (obj.empty()) {
            out += "{}";
            return;
        }
        out.push_back('{');
        bool first = true;
        for (const auto& [k, v] : obj) {
            if (!first) out.push_back(',');
            first = false;
            if (indent >= 0) {
                out.push_back('\n');
                out.append(static_cast<size_t>((depth + 1) * indent), ' ');
            }
            escape_string(k, out);
            out.push_back(':');
            if (indent >= 0) out.push_back(' ');
            dump_impl(v, indent, depth + 1, out);
        }
        if (indent >= 0) {
            out.push_back('\n');
            out.append(static_cast<size_t>(depth * indent), ' ');
        }
        out.push_back('}');
    }
}

class Parser {
public:
    explicit Parser(std::string_view input) : input_(input) {}

    Value parse_root() {
        skip_ws();
        Value v = parse_value();
        skip_ws();
        if (pos_ != input_.size()) {
            throw ParseError("Unexpected trailing characters at offset " + std::to_string(pos_));
        }
        return v;
    }

private:
    std::string_view input_;
    size_t pos_ = 0;

    void skip_ws() {
        while (pos_ < input_.size()) {
            char c = input_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    char peek() const {
        if (pos_ >= input_.size()) {
            throw ParseError("Unexpected end of JSON input");
        }
        return input_[pos_];
    }

    char consume() {
        char c = peek();
        ++pos_;
        return c;
    }

    Value parse_value() {
        skip_ws();
        char c = peek();
        if (c == '{') return parse_object();
        if (c == '[') return parse_array();
        if (c == '"') return Value(parse_string());
        if (c == 't') return parse_literal("true", Value(true));
        if (c == 'f') return parse_literal("false", Value(false));
        if (c == 'n') return parse_literal("null", Value(nullptr));
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        throw ParseError(std::string("Unexpected character '") + c + "' at offset " + std::to_string(pos_));
    }

    Value parse_literal(std::string_view lit, Value result) {
        if (input_.substr(pos_, lit.size()) != lit) {
            throw ParseError("Invalid literal at offset " + std::to_string(pos_));
        }
        pos_ += lit.size();
        return result;
    }

    static void append_utf8(uint32_t cp, std::string& out) {
        if (cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0x10FFFF) {
            out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    uint32_t parse_hex4() {
        if (pos_ + 4 > input_.size()) {
            throw ParseError("Incomplete unicode escape");
        }
        uint32_t val = 0;
        for (int i = 0; i < 4; ++i) {
            char c = input_[pos_++];
            val <<= 4;
            if (c >= '0' && c <= '9') val |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') val |= static_cast<uint32_t>(10 + c - 'a');
            else if (c >= 'A' && c <= 'F') val |= static_cast<uint32_t>(10 + c - 'A');
            else throw ParseError("Invalid hex digit in unicode escape");
        }
        return val;
    }

    std::string parse_string() {
        if (consume() != '"') throw ParseError("Expected '\"'");
        std::string out;
        while (pos_ < input_.size()) {
            char c = consume();
            if (c == '"') return out;
            if (c == '\\') {
                char esc = consume();
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp = parse_hex4();
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (pos_ + 2 <= input_.size() && input_[pos_] == '\\' && input_[pos_ + 1] == 'u') {
                                pos_ += 2;
                                uint32_t low = parse_hex4();
                                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                            }
                        }
                        append_utf8(cp, out);
                        break;
                    }
                    default:
                        throw ParseError("Invalid escape sequence");
                }
            } else {
                out.push_back(c);
            }
        }
        throw ParseError("Unterminated JSON string");
    }

    Value parse_number() {
        size_t start = pos_;
        if (input_[pos_] == '-') ++pos_;
        bool is_float = false;
        while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
        if (pos_ < input_.size() && input_[pos_] == '.') {
            is_float = true;
            ++pos_;
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            is_float = true;
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
        }
        std::string num_str(input_.substr(start, pos_ - start));
        if (!is_float) {
            int64_t val = 0;
            auto [ptr, ec] = std::from_chars(num_str.data(), num_str.data() + num_str.size(), val);
            if (ec == std::errc{} && ptr == num_str.data() + num_str.size()) {
                return Value(val);
            }
        }
        try {
            return Value(std::stod(num_str));
        } catch (...) {
            throw ParseError("Invalid number: " + num_str);
        }
    }

    Value parse_array() {
        consume();  // '['
        Value::Array arr;
        skip_ws();
        if (peek() == ']') {
            consume();
            return Value(std::move(arr));
        }
        while (true) {
            arr.push_back(parse_value());
            skip_ws();
            char c = consume();
            if (c == ']') break;
            if (c != ',') throw ParseError("Expected ',' or ']' in array");
        }
        return Value(std::move(arr));
    }

    Value parse_object() {
        consume();  // '{'
        Value::Object obj;
        skip_ws();
        if (peek() == '}') {
            consume();
            return Value(std::move(obj));
        }
        while (true) {
            skip_ws();
            std::string key = parse_string();
            skip_ws();
            if (consume() != ':') throw ParseError("Expected ':' after object key");
            obj.emplace(std::move(key), parse_value());
            skip_ws();
            char c = consume();
            if (c == '}') break;
            if (c != ',') throw ParseError("Expected ',' or '}' in object");
        }
        return Value(std::move(obj));
    }
};

}  // namespace

std::string Value::dump(int indent) const {
    std::string out;
    dump_impl(*this, indent, 0, out);
    return out;
}

Value parse(std::string_view input) {
    Parser parser(input);
    return parser.parse_root();
}

Value parse_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        throw ParseError("Failed to open JSON file: " + path);
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return parse(oss.str());
}

}  // namespace procsnap::json
