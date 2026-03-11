import "./vanta/vanta.birds.js";

window.addEventListener("DOMContentLoaded", () => {
  if (!window.VANTA || !window.VANTA.BIRDS) {
    return;
  }

  window.VANTA.BIRDS({
    el: "#heroScene",
    mouseControls: true,
    touchControls: true,
    gyroControls: false,
    minHeight: 200,
    minWidth: 200,
    backgroundColor: 0x12081f,
    color1: 0xc084fc,
    color2: 0x8b5cf6,
    birdSize: 1.1,
    wingSpan: 22,
    speedLimit: 4.5,
    separation: 34,
    alignment: 24,
    cohesion: 28,
    quantity: 4
  });
});
