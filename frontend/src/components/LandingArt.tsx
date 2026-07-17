"use client";

/**
 * Subtle monochrome graffiti / stencil art for the empty landing canvas.
 * Decorative only — pure SVG, no text, no network assets.
 */
export function LandingArt() {
  return (
    <div className="landing-art" aria-hidden>
      <svg
        viewBox="0 0 1600 900"
        preserveAspectRatio="xMidYMid slice"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <pattern
            id="landing-grid"
            width="48"
            height="48"
            patternUnits="userSpaceOnUse"
          >
            <path
              d="M48 0H0V48"
              fill="none"
              stroke="#e8e8e8"
              strokeWidth="1"
            />
          </pattern>
          <linearGradient id="landing-fade" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#f5f5f5" stopOpacity="0" />
            <stop offset="50%" stopColor="#f0f0f0" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#ebebeb" stopOpacity="0" />
          </linearGradient>
          <radialGradient id="landing-center-clear" cx="50%" cy="48%" r="42%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.92" />
            <stop offset="55%" stopColor="#ffffff" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </radialGradient>
        </defs>

        <rect width="1600" height="900" fill="#ffffff" />
        <rect width="1600" height="900" fill="url(#landing-grid)" />
        <rect width="1600" height="900" fill="url(#landing-fade)" />

        {/* Abstract spray / tag strokes */}
        <g fill="none" stroke="#d0d0d0" strokeWidth="3" strokeLinecap="round" opacity="0.55">
          <path d="M120 480 C200 420, 280 560, 360 500 S520 440, 600 520" />
          <path d="M1280 120 C1360 180, 1420 80, 1500 160" />
          <path d="M40 780 C180 740, 260 860, 420 800" strokeWidth="2" />
          <path d="M900 40 L940 100 L980 50 L1020 110" strokeWidth="2" />
          <path d="M720 820 C800 760, 880 880, 980 800 S1120 740, 1200 820" strokeWidth="2.5" />
          <path d="M200 100 C280 60, 340 140, 420 90" strokeWidth="2" />
        </g>

        {/* Stencil blocks / tags (no lettering) */}
        <g fill="#e4e4e4" opacity="0.55">
          <path d="M80 140l48-18 12 36-48 18z" />
          <path d="M1400 640l60-24 16 40-60 24z" />
          <circle cx="1320" cy="200" r="28" fill="none" stroke="#d8d8d8" strokeWidth="3" opacity="0.8" />
          <circle cx="1320" cy="200" r="12" fill="none" stroke="#d8d8d8" strokeWidth="2" opacity="0.8" />
        </g>

        {/* Circuit / config glyph cluster (left) */}
        <g
          fill="none"
          stroke="#cfcfcf"
          strokeWidth="1.5"
          opacity="0.5"
          transform="translate(60 280)"
        >
          <rect x="0" y="0" width="72" height="48" rx="2" />
          <path d="M12 16h48M12 24h36M12 32h42" />
          <circle cx="100" cy="24" r="10" />
          <path d="M72 24h18" />
          <path d="M110 24h40v-20h30" />
          <rect x="180" y="0" width="40" height="40" />
          <path d="M190 10h20v20h-20z" />
          <path d="M220 20h50" />
          <circle cx="280" cy="20" r="6" />
          <path d="M0 70h120M0 90h80M40 70v40" />
          <path d="M160 80c40-30 80 30 120 0" />
          <rect x="290" y="60" width="50" height="28" rx="2" />
        </g>

        {/* Right-side mesh / tags */}
        <g
          fill="none"
          stroke="#d0d0d0"
          strokeWidth="1.5"
          opacity="0.45"
          transform="translate(1180 380)"
        >
          <path d="M0 0l40 20-40 20z" />
          <path d="M50 10h80v40h-80z" />
          <path d="M60 20h60M60 30h40M60 40h50" />
          <path d="M140 30c30-40 80-40 110 0" />
          <circle cx="260" cy="30" r="14" />
          <path d="M246 30h28M260 16v28" />
          <path d="M20 80h100M20 100h70M50 80v40" />
        </g>

        {/* Bottom-left stack of abstract tags */}
        <g
          fill="none"
          stroke="#d2d2d2"
          strokeWidth="2"
          opacity="0.4"
          transform="translate(100 620)"
        >
          <rect x="0" y="0" width="90" height="28" rx="3" />
          <rect x="20" y="36" width="110" height="28" rx="3" transform="rotate(-4 20 36)" />
          <rect x="8" y="72" width="70" height="24" rx="3" transform="rotate(3 8 72)" />
          <path d="M140 20c20-25 55-20 70 8" />
          <circle cx="220" cy="40" r="18" />
          <path d="M208 40h24M220 28v24" strokeWidth="1.5" />
        </g>

        {/* Top-right constellation */}
        <g fill="#d8d8d8" opacity="0.35">
          <circle cx="1280" cy="80" r="3" />
          <circle cx="1320" cy="110" r="2" />
          <circle cx="1360" cy="70" r="2.5" />
          <circle cx="1400" cy="130" r="2" />
          <circle cx="1450" cy="90" r="3" />
          <path
            d="M1280 80L1320 110L1360 70L1400 130L1450 90"
            fill="none"
            stroke="#d8d8d8"
            strokeWidth="1"
          />
        </g>

        {/* Diagonal hatch bands (spray-paint vibe) */}
        <g opacity="0.16" stroke="#bbb" strokeWidth="1">
          {Array.from({ length: 18 }).map((_, i) => (
            <line
              key={i}
              x1={-100 + i * 28}
              y1="900"
              x2={200 + i * 28}
              y2="0"
            />
          ))}
        </g>
        <g opacity="0.11" stroke="#ccc" strokeWidth="1">
          {Array.from({ length: 12 }).map((_, i) => (
            <line
              key={i}
              x1={900 + i * 36}
              y1="0"
              x2={600 + i * 36}
              y2="900"
            />
          ))}
        </g>

        {/* Corner brackets */}
        <g fill="none" stroke="#c8c8c8" strokeWidth="2" opacity="0.5">
          <path d="M24 80V24h56" />
          <path d="M1576 80V24h-56" />
          <path d="M24 820v56h56" />
          <path d="M1576 820v56h-56" />
        </g>

        {/* Soft vignette so center form stays readable */}
        <rect width="1600" height="900" fill="url(#landing-center-clear)" />
      </svg>
    </div>
  );
}
