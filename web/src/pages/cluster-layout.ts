const LEADER_W = 204;
const LEADER_H = 84;
const FOLLOWER_W = 184;
const FOLLOWER_H = 72;
const MEMBER_GAP = 22;
const MEMBER_PAD = 28;

interface LayoutNode {
  id: string;
  role?: string;
}

export interface MemberBox {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface MemberLayout {
  width: number;
  height: number;
  leaderId?: string;
  positions: Map<string, MemberBox>;
}

function boxesClear(a: MemberBox, b: MemberBox, gap: number) {
  return Math.abs(a.x - b.x) >= (a.w + b.w) / 2 + gap
    || Math.abs(a.y - b.y) >= (a.h + b.h) / 2 + gap;
}

export function rectEdge(box: MemberBox, ux: number, uy: number) {
  const tx = ux === 0 ? Infinity : (box.w / 2) / Math.abs(ux);
  const ty = uy === 0 ? Infinity : (box.h / 2) / Math.abs(uy);
  const t = Math.min(tx, ty);
  return { x: box.x + ux * t, y: box.y + uy * t };
}

// Place the leader at the hub and followers on an orbit sized so the cards
// themselves never share space. The radius grows with membership; labels live
// inside the cards, so a larger set does not pile text onto neighbouring nodes.
export function layoutMembers(nodes: LayoutNode[], leaderId: string): MemberLayout {
  const leader = nodes.find(n => n.id === leaderId) || nodes.find(n => n.role === 'leader') || nodes[0];
  if (!leader) {
    return { width: 320, height: 160, positions: new Map() };
  }
  const followers = nodes.filter(n => n.id !== leader.id);
  const n = followers.length;
  const start = n === 2 ? 0 : -Math.PI / 2;

  const placed = (radius: number, yScale: number): MemberBox[] => {
    const lead: MemberBox = { id: leader.id, x: 0, y: 0, w: LEADER_W, h: LEADER_H };
    const rest = followers.map((node, i) => {
      const angle = start + (2 * Math.PI * i) / n;
      return {
        id: node.id,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius * yScale,
        w: FOLLOWER_W,
        h: FOLLOWER_H,
      };
    });
    return [lead, ...rest];
  };

  const clearAt = (radius: number, yScale: number) => {
    const boxes = placed(radius, yScale);
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        if (!boxesClear(boxes[i], boxes[j], MEMBER_GAP)) return false;
      }
    }
    return true;
  };

  let radius = 0;
  let yScale = 1;
  if (n > 0) {
    let lo = 0;
    let hi = 80;
    while (!clearAt(hi, 1) && hi < 8000) hi *= 2;
    for (let i = 0; i < 28; i++) {
      const mid = (lo + hi) / 2;
      if (clearAt(mid, 1)) hi = mid;
      else lo = mid;
    }
    radius = hi;

    // Cards are wider than they are tall, so a circle leaves a tall empty
    // band above and below the leader. Pull the orbit in vertically until
    // the same gap used horizontally is all that remains.
    let yLo = 0.35;
    let yHi = 1;
    if (clearAt(radius, yLo)) yHi = yLo;
    else {
      for (let i = 0; i < 20; i++) {
        const mid = (yLo + yHi) / 2;
        if (clearAt(radius, mid)) yHi = mid;
        else yLo = mid;
      }
    }
    yScale = yHi;
  }

  const boxes = placed(radius, yScale);
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const b of boxes) {
    minX = Math.min(minX, b.x - b.w / 2);
    minY = Math.min(minY, b.y - b.h / 2);
    maxX = Math.max(maxX, b.x + b.w / 2);
    maxY = Math.max(maxY, b.y + b.h / 2);
  }
  const width = Math.ceil(maxX - minX + MEMBER_PAD * 2);
  const height = Math.ceil(maxY - minY + MEMBER_PAD * 2);
  const ox = -minX + MEMBER_PAD;
  const oy = -minY + MEMBER_PAD;
  const positions = new Map<string, MemberBox>();
  for (const b of boxes) {
    positions.set(b.id, { ...b, x: b.x + ox, y: b.y + oy });
  }
  return { width, height, leaderId: leader.id, positions };
}
