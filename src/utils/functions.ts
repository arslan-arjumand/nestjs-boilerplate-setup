export function randomNumber(length: number) {
  return String(
    Math.floor(
      Math.pow(10, length - 1) +
        Math.random() * (Math.pow(10, length) - Math.pow(10, length - 1) - 1),
    ),
  );
}
