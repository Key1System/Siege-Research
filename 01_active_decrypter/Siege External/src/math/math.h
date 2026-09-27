#pragma once
#include <cstdint>
#include <cmath>

namespace math {

struct Vec3 {
    float x = 0.f, y = 0.f, z = 0.f;
};

struct Vec2 {
    float x = 0.f, y = 0.f;
};

struct Mat4 {
    float m[16] = {};
    float& operator[](int i) { return m[i]; }
    float  operator[](int i) const { return m[i]; }
};

inline bool world_to_screen(const Mat4& view_proj,
                            const Vec3& world,
                            float screen_w, float screen_h,
                            Vec2& out_screen)
{
    const float* v = view_proj.m;
    float cx = world.x * v[0]  + world.y * v[4]  + world.z * v[8]  + v[12];
    float cy = world.x * v[1]  + world.y * v[5]  + world.z * v[9]  + v[13];
    float cw = world.x * v[3]  + world.y * v[7]  + world.z * v[11] + v[15];

    if (cw < 0.001f) return false;

    float inv = 1.0f / cw;
    out_screen.x = (screen_w * 0.5f) + (cx * inv) * (screen_w * 0.5f);
    out_screen.y = (screen_h * 0.5f) - (cy * inv) * (screen_h * 0.5f);
    return true;
}

inline float dist(const Vec3& a, const Vec3& b) {
    float dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

} // namespace math
