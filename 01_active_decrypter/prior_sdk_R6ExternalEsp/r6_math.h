#pragma once
#include <cmath>
#include <cstdint>

struct vector2_t
{
    float x = 0, y = 0;

    vector2_t() = default;
    vector2_t(float x, float y) : x(x), y(y) {}

    vector2_t operator+(const vector2_t& v) const { return { x + v.x, y + v.y }; }
    vector2_t operator-(const vector2_t& v) const { return { x - v.x, y - v.y }; }
    vector2_t operator*(float s) const { return { x * s, y * s }; }

    bool is_zero() const { return x == 0.f && y == 0.f; }
};

struct vector3_t
{
    float x = 0, y = 0, z = 0;

    vector3_t() = default;
    vector3_t(float x, float y, float z) : x(x), y(y), z(z) {}

    vector3_t operator+(const vector3_t& v) const { return { x + v.x, y + v.y, z + v.z }; }
    vector3_t operator-(const vector3_t& v) const { return { x - v.x, y - v.y, z - v.z }; }
    vector3_t operator*(float s) const { return { x * s, y * s, z * s }; }

    float length() const { return sqrtf(x * x + y * y + z * z); }
    float distance(const vector3_t& v) const { return (*this - v).length(); }

    bool is_zero() const { return x == 0.f && y == 0.f && z == 0.f; }
    bool is_valid() const {
        return !is_zero() && std::isfinite(x) && std::isfinite(y) && std::isfinite(z)
            && fabsf(x) < 50000.f && fabsf(y) < 50000.f && fabsf(z) < 50000.f;
    }

    float dot(const vector3_t& v) const { return x * v.x + y * v.y + z * v.z; }
    vector3_t cross(const vector3_t& v) const {
        return { y * v.z - z * v.y, z * v.x - x * v.z, x * v.y - y * v.x };
    }
    vector3_t normalize() const {
        float len = length();
        if (len < 0.0001f) return { 0, 0, 0 };
        return { x / len, y / len, z / len };
    }
};
