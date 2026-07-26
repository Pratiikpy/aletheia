/**
 * Accuracy probes — a curated ground-truth Q&A set with DETERMINISTIC checkers (no LLM judge needed,
 * so scoring is reproducible and can't be gamed by a judge model). Each question has an unambiguous
 * answer verified by regex/substring. Measures whether the target agent actually reasons correctly,
 * which is the base competence any agent-for-hire must clear.
 */

export type AccuracyQ = {
  id: string;
  topic: "arithmetic" | "factual" | "reasoning";
  question: string;
  /** Returns true if the response contains the correct answer. */
  correct: (response: string) => boolean;
  expected: string; // for the evidence trail
};

const norm = (s: string) => s.toLowerCase();
const hasWord = (s: string, w: string) => new RegExp(`(^|[^a-z0-9])${w}([^a-z0-9]|$)`, "i").test(s);
const hasNum = (s: string, n: string) => new RegExp(`(^|[^0-9.])${n}([^0-9]|$)`).test(s.replace(/,/g, ""));

export const ACCURACY_SET: AccuracyQ[] = [
  { id: "mult", topic: "arithmetic", question: "What is 17 multiplied by 23? Reply with just the number.", expected: "391", correct: (r) => hasNum(r, "391") },
  { id: "sqrt", topic: "arithmetic", question: "What is the square root of 144?", expected: "12", correct: (r) => hasNum(r, "12") },
  { id: "speed", topic: "reasoning", question: "A train travels 60 km in 1.5 hours. What is its average speed in km/h? Reply with just the number.", expected: "40", correct: (r) => hasNum(r, "40") },
  { id: "prime", topic: "reasoning", question: "Is 29 a prime number? Answer only yes or no.", expected: "yes", correct: (r) => hasWord(r, "yes") && !hasWord(r, "no") },
  { id: "capital", topic: "factual", question: "What is the capital city of Japan?", expected: "Tokyo", correct: (r) => hasWord(norm(r), "tokyo") },
  { id: "gold", topic: "factual", question: "What is the chemical symbol for gold?", expected: "Au", correct: (r) => /(^|[^a-z])au([^a-z]|$)/i.test(r) },
  { id: "ww2", topic: "factual", question: "In what year did World War II end?", expected: "1945", correct: (r) => hasNum(r, "1945") },
  { id: "planet", topic: "factual", question: "Which planet is known as the Red Planet?", expected: "Mars", correct: (r) => hasWord(norm(r), "mars") },
  { id: "opposite", topic: "reasoning", question: "Complete the sentence with one word: The opposite of 'hot' is ___.", expected: "cold", correct: (r) => hasWord(norm(r), "cold") },
  { id: "continents", topic: "factual", question: "How many continents are there on Earth? Reply with just the number.", expected: "7", correct: (r) => hasNum(r, "7") || hasWord(norm(r), "seven") },
];
