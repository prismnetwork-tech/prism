"use client";

import { useEffect, useRef } from "react";

type Point = {
  x: number;
  y: number;
};

type Frame = {
  context: CanvasRenderingContext2D;
  width: number;
  height: number;
  time: number;
};

export function HeroSignal() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;

    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0;
    let height = 0;
    let visible = true;
    let width = 0;

    const render = (time: number) => {
      context.clearRect(0, 0, width, height);
      paintPrism({
        context,
        width,
        height,
        time: motion.matches ? 2800 : time,
      });
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
        render(2800);
        return;
      }
      frame = window.requestAnimationFrame(draw);
    };

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      const pixelRatio = Math.min(window.devicePixelRatio || 1, 1.75);
      width = bounds.width;
      height = bounds.height;
      canvas.width = Math.round(width * pixelRatio);
      canvas.height = Math.round(height * pixelRatio);
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
      if (motion.matches) render(2800);
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

    intersectionObserver.observe(canvas);
    resizeObserver.observe(canvas);
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
      <canvas ref={canvasRef} aria-label="GPU lease refracting into escrow, compute and settlement paths" role="img" />
      <div className="signal-corner signal-corner-top" aria-hidden="true" />
      <div className="signal-corner signal-corner-bottom" aria-hidden="true" />
      <div className="signal-hud" aria-hidden="true">
        <span>LEASE SIGNAL / 001</span>
        <strong>PRISM REFRACTION</strong>
      </div>
    </div>
  );
}

function paintPrism({ context, width, height, time }: Frame) {
  const compact = width < 520;
  const wide = width >= 960;

  paintBackdrop(context, width, height);
  paintPerspectiveGrid(
    context,
    width,
    height,
    width * (wide ? 0.64 : 0.5),
    height * (compact ? 0.58 : 0.36),
  );

  const scale = Math.min(width, height);
  const center = {
    x: width * (compact ? 0.46 : wide ? 0.64 : 0.58),
    y: height * (compact ? 0.79 : 0.52),
  };
  const apex = { x: center.x, y: center.y - scale * 0.23 };
  const left = { x: center.x - scale * 0.2, y: center.y + scale * 0.17 };
  const right = { x: center.x + scale * 0.21, y: center.y + scale * 0.17 };
  const core = { x: center.x, y: center.y + scale * 0.04 };

  context.save();
  context.shadowColor = "rgba(204, 255, 0, 0.4)";
  context.shadowBlur = 26;
  context.lineWidth = 1.4;
  context.strokeStyle = "rgba(204, 255, 0, 0.9)";
  context.fillStyle = "rgba(204, 255, 0, 0.035)";
  polygon(context, [apex, left, right]);
  context.fill();
  context.stroke();
  context.shadowBlur = 0;
  context.strokeStyle = "rgba(204, 255, 0, 0.35)";
  line(context, apex, core);
  line(context, left, core);
  line(context, right, core);
  context.restore();

  const origin = { x: width * (wide ? 0.38 : compact ? 0.04 : 0.18), y: center.y };
  const beamEnd = { x: center.x - scale * 0.05, y: center.y - scale * 0.06 };
  const incoming = pointBetween(origin, beamEnd, loop(time, 4400));

  context.save();
  context.strokeStyle = "rgba(204, 255, 0, 0.3)";
  context.lineWidth = 1;
  line(context, origin, beamEnd);
  glowPoint(context, incoming.x, incoming.y, 3.5, 18);
  context.restore();
  label(context, "LEASE REQUEST", origin.x, origin.y - 18, "left");

  const lanes = [
    { name: "ESCROW", offset: 0 },
    { name: "COMPUTE", offset: 0.34 },
    { name: "SETTLE", offset: 0.68 },
  ] as const;
  const receipt = {
    x: width * (compact ? 0.75 : wide ? 0.87 : 0.82),
    y: height * (compact ? 0.66 : 0.39),
    width: width * (compact ? 0.21 : wide ? 0.105 : 0.14),
    height: height * (compact ? 0.17 : 0.22),
  };

  lanes.forEach((lane) => {
    const start = { x: center.x + scale * 0.07, y: center.y };
    const end = {
      x: receipt.x,
      y: receipt.y + receipt.height * (lane.name === "ESCROW" ? 0.25 : lane.name === "COMPUTE" ? 0.5 : 0.75),
    };
    const checkpointX = width * (compact ? 0.63 : wide ? 0.78 : 0.7);
    const checkpoint = pointBetween(start, end, (checkpointX - start.x) / (end.x - start.x));

    context.save();
    context.strokeStyle = "rgba(204, 255, 0, 0.32)";
    context.lineWidth = lane.name === "COMPUTE" ? 1.4 : 1;
    line(context, start, end);
    diamond(context, checkpoint.x, checkpoint.y, 7);
    label(context, lane.name, checkpoint.x + 13, checkpoint.y - 9, "left");

    const progress = loop(time + lane.offset * 4400, 4400);
    const point = pointBetween(start, end, progress);
    glowPoint(context, point.x, point.y, lane.name === "COMPUTE" ? 3.5 : 2.5, 15);
    context.restore();
  });

  context.save();
  context.fillStyle = "rgba(3, 5, 1, 0.92)";
  context.strokeStyle = "rgba(204, 255, 0, 0.7)";
  context.lineWidth = 1;
  context.fillRect(receipt.x, receipt.y, receipt.width, receipt.height);
  context.strokeRect(receipt.x, receipt.y, receipt.width, receipt.height);
  context.fillStyle = "#ccff00";
  context.fillRect(receipt.x, receipt.y, receipt.width, 2);
  label(context, "RECEIPT", receipt.x + 10, receipt.y + 22, "left", "#ccff00");
  label(context, "RUNTIME", receipt.x + 10, receipt.y + 48, "left");
  label(
    context,
    `${String(Math.floor((time / 1000) % 60)).padStart(2, "0")}.00 SEC`,
    receipt.x + 10,
    receipt.y + 65,
    "left",
    "#f4f7ef",
  );
  label(
    context,
    compact ? "FINAL" : "FINALIZED",
    receipt.x + 10,
    receipt.y + receipt.height - 15,
    "left",
    "#ccff00",
  );
  context.restore();
}

function paintBackdrop(context: CanvasRenderingContext2D, width: number, height: number) {
  const compact = width < 520;
  const wide = width >= 960;
  const focusX = wide ? 0.7 : compact ? 0.5 : 0.58;
  const focusY = compact ? 0.68 : 0.42;

  context.fillStyle = "#010200";
  context.fillRect(0, 0, width, height);
  const glow = context.createRadialGradient(
    width * focusX,
    height * focusY,
    0,
    width * focusX,
    height * focusY,
    Math.max(width, height) * 0.68,
  );
  glow.addColorStop(0, "rgba(204, 255, 0, 0.1)");
  glow.addColorStop(0.42, "rgba(204, 255, 0, 0.025)");
  glow.addColorStop(1, "rgba(204, 255, 0, 0)");
  context.fillStyle = glow;
  context.fillRect(0, 0, width, height);
}

function paintPerspectiveGrid(
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  vanishingX: number,
  horizon: number,
) {
  context.save();
  context.strokeStyle = "rgba(204, 255, 0, 0.055)";
  context.lineWidth = 1;
  for (let column = -3; column <= 11; column += 1) {
    line(
      context,
      { x: vanishingX, y: horizon },
      { x: (column / 8) * width, y: height * 1.05 },
    );
  }
  for (let row = 0; row < 8; row += 1) {
    const depth = row / 7;
    const y = horizon + Math.pow(depth, 2.1) * (height - horizon);
    line(context, { x: 0, y }, { x: width, y });
  }
  context.restore();
}

function polygon(context: CanvasRenderingContext2D, points: ReadonlyArray<Point>) {
  context.beginPath();
  points.forEach((point, index) => {
    if (index === 0) context.moveTo(point.x, point.y);
    else context.lineTo(point.x, point.y);
  });
  context.closePath();
}

function line(context: CanvasRenderingContext2D, start: Point, end: Point) {
  context.beginPath();
  context.moveTo(start.x, start.y);
  context.lineTo(end.x, end.y);
  context.stroke();
}

function diamond(context: CanvasRenderingContext2D, x: number, y: number, size: number) {
  context.save();
  context.translate(x, y);
  context.rotate(Math.PI / 4);
  context.fillStyle = "rgba(2, 4, 0, 0.9)";
  context.strokeStyle = "#ccff00";
  context.lineWidth = 1.2;
  context.fillRect(-size / 2, -size / 2, size, size);
  context.strokeRect(-size / 2, -size / 2, size, size);
  context.restore();
}

function glowPoint(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
  blur: number,
) {
  context.save();
  context.shadowColor = "#ccff00";
  context.shadowBlur = blur;
  context.fillStyle = "#ccff00";
  context.beginPath();
  context.arc(x, y, radius, 0, Math.PI * 2);
  context.fill();
  context.restore();
}

function label(
  context: CanvasRenderingContext2D,
  text: string,
  x: number,
  y: number,
  align: CanvasTextAlign,
  color = "rgba(226, 233, 220, 0.5)",
) {
  context.save();
  context.fillStyle = color;
  context.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.letterSpacing = "1px";
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

function loop(time: number, duration: number) {
  return (time % duration) / duration;
}
