#pragma once
#include "../game/cache.h"
#include "../game/view.h"
#include "../game/bones.h"
#include "../math/math.h"
#include "../../third_party/imgui/imgui.h"
#include <vector>

namespace esp {

struct Config {
    bool  boxes         = true;
    bool  name          = true;
    bool  distance      = true;
    bool  bones             = true;          // draw bone dots + indices
    bool  bone_labels       = true;          // draw the numeric label next to each dot
    float max_distance      = 500.f;         // meters (game units)
    float bone_dot_r        = 3.f;           // radius of bone dots
    ImU32 col_box       = IM_COL32(0, 255, 128, 255);
    ImU32 col_shadow    = IM_COL32(0, 0, 0, 200);
    ImU32 col_bone      = IM_COL32(255, 210, 60, 255);
    ImU32 col_bone_lbl  = IM_COL32(255, 240, 200, 255);
};

inline void render(const game::EntityCache& cache,
                   const game::ViewData& vd,
                   const Config& cfg,
                   float sw, float sh)
{
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    for (const auto& e : cache.entities()) {
        if (!e.valid) continue;

        float d = math::dist(e.pos, vd.cam_pos);
        if (d > cfg.max_distance) continue;

        // Box: project foot + head (approx 1.9 game units above the CC).
        math::Vec3 head = { e.pos.x, e.pos.y, e.pos.z + 1.9f };
        math::Vec2 s_foot{}, s_head{};
        if (!math::world_to_screen(vd.view_proj, e.pos,  sw, sh, s_foot)) continue;
        if (!math::world_to_screen(vd.view_proj, head,   sw, sh, s_head)) continue;

        float h = std::abs(s_foot.y - s_head.y);
        float w = h * 0.4f;
        float x = s_foot.x - w * 0.5f;
        float y = s_head.y;

        if (cfg.boxes) {
            dl->AddRect(ImVec2(x - 1, y - 1),
                        ImVec2(x + w + 1, y + h + 1),
                        cfg.col_shadow, 0.f, 0, 2.f);
            dl->AddRect(ImVec2(x, y),
                        ImVec2(x + w, y + h),
                        cfg.col_box, 0.f, 0, 1.f);
        }

        if (cfg.distance) {
            char buf[24];
            snprintf(buf, sizeof(buf), "[%.0fm]", d);
            ImVec2 sz = ImGui::CalcTextSize(buf);
            ImVec2 pos{ s_foot.x - sz.x * 0.5f, y + h + 2 };
            dl->AddText(ImVec2(pos.x + 1, pos.y + 1), cfg.col_shadow, buf);
            dl->AddText(pos, cfg.col_box, buf);
        }
    }
}

// Draw each SkelComp's bone slots as numbered dots. Bones are drawn at
// (character_world_pos + local_bone_offset) — see game::approx_world.
// This is an APPROXIMATION for visualization; the local offsets are
// static (bind-pose) not per-frame animated. Useful for identifying
// which slot corresponds to which body part visually.
inline void render_bones(const std::vector<game::Character>& chars,
                         const game::ViewData& vd,
                         const Config& cfg,
                         float sw, float sh)
{
    if (!cfg.bones) return;
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    for (const auto& ch : chars) {
        if (ch.cc == 0) continue;   // no CC match ⇒ no world pos
        float d = math::dist(ch.world_pos, vd.cam_pos);
        if (d > cfg.max_distance) continue;

        // Draw EVERY valid bone slot — no motion filtering. The index
        // label lets us identify each visually.
        for (const auto& b : ch.bones) {
            math::Vec3 world = game::approx_world(ch, b);
            math::Vec2 s{};
            if (!math::world_to_screen(vd.view_proj, world, sw, sh, s)) continue;

            dl->AddCircleFilled(ImVec2(s.x, s.y), cfg.bone_dot_r + 1,
                                cfg.col_shadow, 12);
            dl->AddCircleFilled(ImVec2(s.x, s.y), cfg.bone_dot_r,
                                cfg.col_bone, 12);

            if (cfg.bone_labels) {
                char lbl[8];
                snprintf(lbl, sizeof(lbl), "%d", b.index);
                dl->AddText(ImVec2(s.x + 5, s.y - 6),
                            cfg.col_shadow, lbl);
                dl->AddText(ImVec2(s.x + 4, s.y - 7),
                            cfg.col_bone_lbl, lbl);
            }
        }
    }
}

} // namespace esp
