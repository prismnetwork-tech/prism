"use client";

import { useEffect, useRef } from "react";

type Point = {
  x: number;
  y: number;
};

type Point3 = Point & {
  z: number;
};

type Point4 = Point3 & {
  w: number;
};

type Frame = {
  context: CanvasRenderingContext2D;
  width: number;
  height: number;
  time: number;
};

type Geometry = {
  center: Point;
  radius: number;
  compact: boolean;
};

const LIME = "#cf0";
const TAU = Math.PI * 2;

const streams = [
  { label: "ESCROW", detail: "FUNDS LOCKED", offset: 0 },
  { label: "CUDA", detail: "WORKSPACE LIVE", offset: 0.28 },
  { label: "PROOF", detail: "RECEIPT FINAL", offset: 0.56 },
] as const;

const tesseractVertices = Array.from({ length: 16 }, (_, index): Point4 => ({
  x: index & 1 ? 1 : -1,
  y: index & 2 ? 1 : -1,
  z: index & 4 ? 1 : -1,
  w: index & 8 ? 1 : -1,
}));

const tesseractEdges: Array<[number, number]> = [];

for (let vertex = 0; vertex < tesseractVertices.length; vertex += 1) {
  for (const axis of [1, 2, 4, 8]) {
    if ((vertex & axis) === 0) tesseractEdges.push([vertex, vertex | axis]);
  }
}

export function HeroSignal() {
  const backgroundRef = useRef<HTMLCanvasElement>(null);
  const coreRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const background = backgroundRef.current;
    const core = coreRef.current;
    const backgroundContext = background?.getContext("2d");
    const coreContext = core?.getContext("2d");
    if (!background || !core || !backgroundContext || !coreContext) return;

    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0;
    let height = 0;
    let visible = true;
    let width = 0;

    const render = (time: number) => {
      backgroundContext.clearRect(0, 0, width, height);
      coreContext.clearRect(0, 0, width, height);
      const geometry = getGeometry(width, height);
      paintLightfield({
        context: backgroundContext,
        width,
        height,
        time: motion.matches ? 3600 : time,
      });
      paintMeshes(coreContext, geometry, motion.matches ? 3600 : time);
    };

    const draw = (time: number) => {
      frame = 0;
      if (!visible) return;
      render(time);
      if (!motion.matches) frame = window.requestAnimationFrame(draw);
    };

    const start = () => {
      if (!visible || frame) return;
      if (motion.matches) {
        render(3600);
        return;
      }
      frame = window.requestAnimationFrame(draw);
    };

    const resize = () => {
      const bounds = background.getBoundingClientRect();
      const pixelRatio = Math.min(window.devicePixelRatio || 1, 1.6);
      width = bounds.width;
      height = bounds.height;

      for (const layer of [background, core]) {
        layer.width = Math.round(width * pixelRatio);
        layer.height = Math.round(height * pixelRatio);
      }

      for (const context of [backgroundContext, coreContext]) {
        context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
      }

      render(motion.matches ? 3600 : performance.now());
    };

    const intersectionObserver = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible) {
        start();
      } else if (frame) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      }
    });
    const resizeObserver = new ResizeObserver(resize);
    const handleMotionChange = () => {
      if (frame) window.cancelAnimationFrame(frame);
      frame = 0;
      start();
    };

    intersectionObserver.observe(background);
    resizeObserver.observe(background);
    motion.addEventListener("change", handleMotionChange);
    resize();
    start();

    return () => {
      if (frame) window.cancelAnimationFrame(frame);
      intersectionObserver.disconnect();
      resizeObserver.disconnect();
      motion.removeEventListener("change", handleMotionChange);
    };
  }, []);

  return (
    <div className="signal-visual">
      <canvas
        className="signal-layer signal-layer-background"
        ref={backgroundRef}
        aria-label="A rotating four-dimensional wireframe prism refracting a GPU lease signal into escrow, compute and proof streams"
        role="img"
      />
      <canvas
        className="signal-layer signal-layer-core"
        ref={coreRef}
        aria-hidden="true"
      />
      <div className="signal-corner signal-corner-top" aria-hidden="true" />
      <div className="signal-corner signal-corner-bottom" aria-hidden="true" />
      <div className="signal-hud" aria-hidden="true">
        <span>LEASE SIGNAL / 001</span>
        <strong>PRISM REFRACTION</strong>
      </div>
    </div>
  );
}

function paintLightfield({ context, width, height, time }: Frame) {
  if (!width || !height) return;

  const { center, radius, compact } = getGeometry(width, height);
  paintIncomingSignal(context, width, center, radius, time, compact);
  paintStreams(context, width, height, center, radius, time, compact);
}

function getGeometry(width: number, height: number): Geometry {
  const compact = width < 600;
  const wide = width >= 960;
  const scale = Math.min(width, height);

  return {
    center: {
      x: width * (compact ? 0.52 : wide ? 0.74 : 0.66),
      y: height * (compact ? 0.73 : 0.5),
    },
    radius: scale * (compact ? 0.25 : wide ? 0.205 : 0.22),
    compact,
  };
}

function paintIncomingSignal(
  context: CanvasRenderingContext2D,
  width: number,
  center: Point,
  radius: number,
  time: number,
  compact: boolean,
) {
  const source = compact
    ? { x: width * 0.05, y: center.y + radius * 0.18 }
    : { x: width * 0.56, y: center.y + radius * 0.08 };
  const impact = {
    x: center.x - radius * 0.12,
    y: center.y - radius * 0.16,
  };

  context.save();
  context.strokeStyle = LIME;
  context.lineWidth = 1;
  line(context, source, impact);

  const progress = loop(time, 3600);
  const point = pointBetween(source, impact, easeInOut(progress));
  paintPoint(context, point.x, point.y, 1.2 + progress);
  context.restore();

  label(
    context,
    "LEASE SIGNAL",
    source.x + (compact ? 12 : 0),
    source.y - 14,
    compact ? "left" : "center",
    LIME,
  );
}

function paintStreams(
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  center: Point,
  radius: number,
  time: number,
  compact: boolean,
) {
  const start = { x: center.x + radius * 0.12, y: center.y };

  streams.forEach((stream, index) => {
    const spread = index - 1;
    const end = compact
      ? {
          x: width * (0.17 + index * 0.33),
          y: height * (0.92 + Math.abs(spread) * 0.018),
        }
      : {
          x: width * 0.975,
          y: center.y + spread * radius * 0.96,
        };

    context.save();
    context.strokeStyle = LIME;
    context.lineWidth = 1;
    line(context, start, end);

    for (let particle = 0; particle < 2; particle += 1) {
      const progress = loop(time + stream.offset * 4800 + particle * 2240, 4800);
      const point = pointBetween(start, end, easeInOut(progress));
      paintPoint(context, point.x, point.y, index === 1 ? 1.8 : 1.3);
    }
    context.restore();

    paintStreamNode(context, end, stream.label, stream.detail, compact);
  });
}

function paintStreamNode(
  context: CanvasRenderingContext2D,
  point: Point,
  title: string,
  detail: string,
  compact: boolean,
) {
  context.save();
  context.translate(point.x, point.y);
  context.strokeStyle = LIME;
  context.fillStyle = "#020300";
  context.lineWidth = 1;
  context.beginPath();
  context.moveTo(0, -6);
  context.lineTo(6, 0);
  context.lineTo(0, 6);
  context.lineTo(-6, 0);
  context.closePath();
  context.fill();
  context.stroke();
  context.restore();

  const x = compact ? point.x : point.x - 14;
  const align = compact ? "center" : "right";
  label(context, title, x, point.y - 17, align, LIME);
  if (!compact) label(context, detail, x, point.y + 21, align, "#f4f7ef");
}

function paintMeshes(
  context: CanvasRenderingContext2D,
  { center, radius }: Geometry,
  time: number,
) {
  paintTesseract(context, center, radius * 0.62, time);
  paintCorePyramid(context, center, radius * 0.19, time);
}

function paintTesseract(
  context: CanvasRenderingContext2D,
  center: Point,
  radius: number,
  time: number,
) {
  const projected = tesseractVertices.map((vertex) => {
    const rotated = rotate4D(vertex, time);
    return project(project4D(rotated), center, radius);
  });

  context.save();
  context.strokeStyle = LIME;
  context.lineWidth = 1;
  for (const [from, to] of tesseractEdges) {
    line(context, projected[from], projected[to]);
  }
  context.restore();
}

function paintCorePyramid(
  context: CanvasRenderingContext2D,
  center: Point,
  radius: number,
  time: number,
) {
  const vertices: Point3[] = [
    { x: 0, y: -1.05, z: 0 },
    { x: -0.76, y: 0.68, z: -0.76 },
    { x: 0.76, y: 0.68, z: -0.76 },
    { x: 0.76, y: 0.68, z: 0.76 },
    { x: -0.76, y: 0.68, z: 0.76 },
  ];
  const rotation = {
    x: time * 0.00042,
    y: -time * 0.00058,
    z: time * 0.00012,
  };
  const projected = vertices.map((vertex) =>
    project(rotate(vertex, rotation), center, radius),
  );
  const edges = [
    [0, 1], [0, 2], [0, 3], [0, 4],
    [1, 2], [2, 3], [3, 4], [4, 1],
  ];

  context.save();
  context.strokeStyle = "#f4f7ef";
  context.lineWidth = 0.75;
  for (const [from, to] of edges) {
    line(context, projected[from], projected[to]);
  }
  context.restore();
}

function rotate4D(point: Point4, time: number): Point4 {
  let { x, y, z, w } = point;

  [x, w] = rotatePair(x, w, time * 0.00021);
  [y, z] = rotatePair(y, z, -time * 0.00016);
  [x, y] = rotatePair(x, y, time * 0.00011);
  [z, w] = rotatePair(z, w, time * 0.00014);

  return { x, y, z, w };
}

function project4D(point: Point4): Point3 {
  const perspective = 4.2 / (4.2 - point.w);
  return {
    x: point.x * perspective,
    y: point.y * perspective,
    z: point.z * perspective,
  };
}

function rotatePair(first: number, second: number, angle: number): [number, number] {
  const cosine = Math.cos(angle);
  const sine = Math.sin(angle);
  return [
    first * cosine - second * sine,
    first * sine + second * cosine,
  ];
}

function rotate(point: Point3, rotation: Point3): Point3 {
  const cosX = Math.cos(rotation.x);
  const sinX = Math.sin(rotation.x);
  const cosY = Math.cos(rotation.y);
  const sinY = Math.sin(rotation.y);
  const cosZ = Math.cos(rotation.z);
  const sinZ = Math.sin(rotation.z);

  const x1 = point.x * cosY - point.z * sinY;
  const z1 = point.x * sinY + point.z * cosY;
  const y1 = point.y * cosX - z1 * sinX;
  const z2 = point.y * sinX + z1 * cosX;

  return {
    x: x1 * cosZ - y1 * sinZ,
    y: x1 * sinZ + y1 * cosZ,
    z: z2,
  };
}

function project(point: Point3, center: Point, radius: number): Point {
  const depth = point.z * radius;
  const perspective = radius * 5.5 / (radius * 5.5 - depth);
  return {
    x: center.x + point.x * radius * perspective,
    y: center.y + point.y * radius * perspective,
  };
}

function line(context: CanvasRenderingContext2D, start: Point, end: Point) {
  context.beginPath();
  context.moveTo(start.x, start.y);
  context.lineTo(end.x, end.y);
  context.stroke();
}

function paintPoint(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
) {
  context.save();
  context.fillStyle = "#f4f7ef";
  context.beginPath();
  context.arc(x, y, radius, 0, TAU);
  context.fill();
  context.restore();
}

function label(
  context: CanvasRenderingContext2D,
  text: string,
  x: number,
  y: number,
  align: CanvasTextAlign,
  color = "#f4f7ef",
) {
  context.save();
  context.fillStyle = color;
  context.font = "8px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.letterSpacing = "1.2px";
  context.textAlign = align;
  context.fillText(text, x, y);
  context.restore();
}

function pointBetween(start: Point, end: Point, progress: number): Point {
  return {
    x: start.x + (end.x - start.x) * progress,
    y: start.y + (end.y - start.y) * progress,
  };
}

function easeInOut(value: number) {
  return value < 0.5
    ? 2 * value * value
    : 1 - Math.pow(-2 * value + 2, 2) / 2;
}

function loop(time: number, duration: number) {
  return (time % duration) / duration;
}
