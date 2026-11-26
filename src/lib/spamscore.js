/** Lightweight pre-flight heuristic. Not a substitute for a real seed test. */
const RULES = [
  { id: 'subject_caps', points: 0.8, test: (m) => (m.subject.match(/[A-Z]/g) || []).length / Math.max(1, m.subject.length) > 0.45 && m.subject.length > 8 },
  { id: 'subject_exclaim', points: 0.5, test: (m) => (m.subject.match(/!/g) || []).length >= 2 },
  { id: 'subject_long', points: 0.4, test: (m) => m.subject.length > 65 },
  { id: 'subject_free', points: 0.4, test: (m) => /\b(free|100%|guarantee|risk.?free)\b/i.test(m.subject) },
  { id: 'spammy_phrases', points: 0.6, test: (m) => (m.text.match(/\b(act now|limited time|click here|buy now|order today|urgent|winner|congratulations)\b/gi) || []).length >= 2 },
  { id: 'money', points: 0.5, test: (m) => (m.text.match(/[$€£]\s?\d/g) || []).length >= 2 },
  { id: 'caps_body', points: 0.7, test: (m) => (m.text.match(/\b[A-Z]{5,}\b/g) || []).length >= 4 },
  { id: 'short_text', points: 0.9, test: (m) => m.text.trim().length < 120 && m.html },
  { id: 'image_only', points: 1.6, test: (m) => m.html && m.text.trim().length < 40 && /<img/i.test(m.html) },
  { id: 'many_links', points: 0.8, test: (m) => (m.html.match(/<a\s/gi) || []).length > 8 },
  { id: 'link_ratio', points: 1.0, test: (m) => m.text.trim() && (m.html.match(/https?:\/\//g) || []).length / Math.max(1, m.text.split(/\s+/).length) > 0.08 },
  { id: 'shortener', points: 0.6, test: (m) => /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd)\b/i.test(m.text + m.html) },
  { id: 'no_unsubscribe', points: 1.2, test: (m) => !m.hasUnsubscribe },
  { id: 'no_plain', points: 1.1, test: (m) => !m.textForCheck },
  { id: 'big_html', points: 0.5, test: (m) => m.html && m.html.length > 120000 },
  { id: 'excessive_hex', points: 0.3, test: (m) => /#[0-9a-f]{6}/i.test(m.html || '') && (m.html.match(/#[0-9a-f]{6}/gi) || []).length > 15 },
  { id: 'tracking_pixel', points: 0.2, test: (m) => /width=["']?1["']?[^>]*height=["']?1/i.test(m.html || '') },
  { id: 'all_caps_word_run', points: 0.5, test: (m) => /\b[A-Z]{8,}\b/.test(m.subject) },
];

export function scoreMessage({ subject, text, html, hasUnsubscribe }) {
  const m = { subject: subject || '', text: text || '', html: html || '', textForCheck: text, hasUnsubscribe };
  const findings = [];
  let score = 0;
  for (const rule of RULES) {
    if (rule.test(m)) { score += rule.points; findings.push(rule.id); }
  }
  return { score: Number(score.toFixed(2)), findings };
}
