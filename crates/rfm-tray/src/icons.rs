//! Menu bar icons, drawn in code as template images: black with varying alpha,
//! which macOS tints for light and dark menu bars.
//!
//! 44×44 pixels: `tray-icon` scales icons to at most 22 points tall, so this is
//! sharp on Retina displays. The glyph is a ring (the mirror):
//!
//! - idle: a ring with a dot at its center
//! - busy: an arc that rotates through `BUSY_FRAMES` frames, around the dot
//! - error: a ring with an exclamation mark inside
//! - offline: a dashed ring

use std::f64::consts::TAU;

use crate::view::IconState;

pub const SIZE: u32 = 44;
pub const BUSY_FRAMES: usize = 8;

const CENTER: f64 = SIZE as f64 / 2.0;
const RING_RADIUS: f64 = 14.0;
const STROKE: f64 = 2.8;
const DOT_RADIUS: f64 = 4.0;
/// Samples per pixel along each axis, for anti-aliasing.
const SUPERSAMPLE: u32 = 4;

/// RGBA pixels for `state`; `frame` animates the busy icon and is ignored
/// otherwise.
pub fn rgba(state: IconState, frame: usize) -> Vec<u8> {
    let rotation = (frame % BUSY_FRAMES) as f64 / BUSY_FRAMES as f64 * TAU;
    let shape = move |x: f64, y: f64| -> bool {
        let (dx, dy) = (x - CENTER, y - CENTER);
        let dist = (dx * dx + dy * dy).sqrt();
        // 0 at twelve o'clock, increasing clockwise.
        let angle = (dx.atan2(-dy) + TAU) % TAU;
        let on_ring = (dist - RING_RADIUS).abs() <= STROKE / 2.0;
        let dot = dist <= DOT_RADIUS;
        match state {
            IconState::Idle => on_ring || dot,
            IconState::Busy => {
                // A 280° arc whose gap travels round.
                let along = (angle - rotation + TAU) % TAU;
                (on_ring && along <= TAU * 280.0 / 360.0) || dot
            }
            IconState::Error => {
                let bar = dx.abs() <= 1.8 && (CENTER - 8.0..=CENTER + 2.5).contains(&y);
                let point = (dx * dx + (y - (CENTER + 6.5)).powi(2)).sqrt() <= 2.0;
                on_ring || bar || point
            }
            IconState::Offline => {
                let dash = (angle / TAU * 10.0).fract() < 0.55;
                on_ring && dash
            }
        }
    };

    let mut pixels = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for py in 0..SIZE {
        for px in 0..SIZE {
            let mut covered = 0;
            for sy in 0..SUPERSAMPLE {
                for sx in 0..SUPERSAMPLE {
                    let x = px as f64 + (sx as f64 + 0.5) / SUPERSAMPLE as f64;
                    let y = py as f64 + (sy as f64 + 0.5) / SUPERSAMPLE as f64;
                    covered += u32::from(shape(x, y));
                }
            }
            let alpha = (covered * 255 / (SUPERSAMPLE * SUPERSAMPLE)) as u8;
            pixels.extend_from_slice(&[0, 0, 0, alpha]);
        }
    }
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage(pixels: &[u8]) -> u32 {
        pixels.chunks(4).map(|p| u32::from(p[3])).sum()
    }

    #[test]
    fn icons_are_template_images_of_the_right_size() {
        for state in [
            IconState::Idle,
            IconState::Busy,
            IconState::Error,
            IconState::Offline,
        ] {
            let pixels = rgba(state, 0);
            assert_eq!(pixels.len(), (SIZE * SIZE * 4) as usize);
            assert!(
                pixels.chunks(4).all(|p| p[..3] == [0, 0, 0]),
                "{state:?}: black only"
            );
            assert!(coverage(&pixels) > 0, "{state:?}: draws something");
            assert!(
                pixels.chunks(4).any(|p| p[3] > 0 && p[3] < 255),
                "{state:?}: anti-aliased"
            );
        }
    }

    #[test]
    fn states_look_different_and_busy_animates() {
        let all: Vec<_> = [
            IconState::Idle,
            IconState::Busy,
            IconState::Error,
            IconState::Offline,
        ]
        .iter()
        .map(|s| rgba(*s, 0))
        .collect();
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
        assert_ne!(rgba(IconState::Busy, 0), rgba(IconState::Busy, 1));
        assert_eq!(
            rgba(IconState::Busy, 0),
            rgba(IconState::Busy, BUSY_FRAMES),
            "frames cycle"
        );
        assert_eq!(
            rgba(IconState::Idle, 0),
            rgba(IconState::Idle, 3),
            "only busy animates"
        );
        assert!(
            coverage(&rgba(IconState::Offline, 0)) < coverage(&rgba(IconState::Idle, 0)),
            "dashed is lighter"
        );
    }

    #[test]
    fn glyph_stays_inside_the_canvas() {
        let pixels = rgba(IconState::Idle, 0);
        let border = (0..SIZE).flat_map(|i| [(i, 0), (i, SIZE - 1), (0, i), (SIZE - 1, i)]);
        assert!(
            border
                .into_iter()
                .all(|(x, y)| pixels[((y * SIZE + x) * 4 + 3) as usize] == 0)
        );
    }
}
