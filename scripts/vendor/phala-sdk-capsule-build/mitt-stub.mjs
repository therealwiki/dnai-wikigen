export default function mitt() {
  return Object.freeze({
    all: new Map(),
    on() {},
    off() {},
    emit() {},
  });
}
