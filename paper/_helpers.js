// IEEE conference-style paper (two-column, US Letter) built with docx-js.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, HeadingLevel,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  ImageRun, SectionType, LineRuleType, TabStopType, VerticalAlign,
} = require("docx");

// ---------------------------------------------------------------- layout
const FONT = "Times New Roman";
const PAGE = { width: 12240, height: 15840 };                  // US Letter
const MARGIN = { top: 1080, bottom: 1440, left: 900, right: 900 }; // 0.75/1/0.625/0.625 in
const TEXT_W = PAGE.width - MARGIN.left - MARGIN.right;        // 10440
const COL_GAP = 360;
const COL_W = Math.floor((TEXT_W - COL_GAP) / 2);              // 5040

// ---------------------------------------------------------------- helpers
const R = (text, o = {}) => new TextRun({ text, font: FONT, size: o.size || 20, bold: o.bold, italics: o.italics, smallCaps: o.smallCaps, superScript: o.sup, subScript: o.sub });

// Markup-aware runs: *italic*  and  _{subscript}
function mk(text, o = {}) {
  const runs = [];
  for (const part of text.split(/(\*[^*]+\*|_\{[^}]+\})/g)) {
    if (!part) continue;
    if (part.startsWith("*") && part.endsWith("*")) runs.push(R(part.slice(1, -1), { ...o, italics: true }));
    else if (part.startsWith("_{")) runs.push(R(part.slice(2, -1), { ...o, sub: true }));
    else runs.push(R(part, o));
  }
  return runs;
}

const P = (runs, o = {}) => new Paragraph({
  alignment: o.align || AlignmentType.JUSTIFIED,
  spacing: { after: o.after ?? 0, before: o.before ?? 0, line: o.line || 240, lineRule: LineRuleType.AUTO },
  indent: o.noIndent ? undefined : { firstLine: o.firstLine ?? 288 },
  keepNext: o.keepNext, keepLines: o.keepLines,
  children: Array.isArray(runs) ? runs : [R(runs, o)],
});

// Body paragraph: takes a string with inline markup  *italic*  and [n] citations kept literal.
function body(text, o = {}) { return P(mk(text), o); }

let secNo = 0, subNo = 0;
const ROMAN = ["I","II","III","IV","V","VI","VII","VIII","IX","X","XI","XII"];
function H1(title) {
  secNo += 1; subNo = 0;
  return new Paragraph({
    alignment: AlignmentType.CENTER, keepNext: true,
    spacing: { before: 200, after: 80 },
    children: [R(`${ROMAN[secNo - 1]}. `, { size: 20 }), R(title.toUpperCase(), { size: 20, smallCaps: false })],
  });
}
function H2(title) {
  subNo += 1;
  return new Paragraph({
    alignment: AlignmentType.LEFT, keepNext: true,
    spacing: { before: 120, after: 40 },
    children: [R(`${String.fromCharCode(64 + subNo)}. `, { italics: true }), R(title, { italics: true })],
  });
}

// Compact caption paragraph
const caption = (label, text, o = {}) => new Paragraph({
  alignment: o.align || AlignmentType.CENTER, keepNext: o.keepNext,
  spacing: { before: o.before ?? 80, after: o.after ?? 120 },
  children: [R(label, { size: 16, smallCaps: true }), ...mk(text, { size: 16 })],
});

// Table with DXA widths that fits in one column
function tbl(headers, rows, widths, o = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const cell = (t, w, hdr, i) => new TableCell({
    width: { size: w, type: WidthType.DXA },
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 30, bottom: 30, left: 60, right: 60 },
    shading: hdr ? { type: ShadingType.CLEAR, fill: "EDEDED", color: "auto" } : undefined,
    children: [new Paragraph({
      alignment: (o.align && o.align[i]) || (i === 0 ? AlignmentType.LEFT : AlignmentType.CENTER),
      spacing: { after: 0 }, keepNext: true, keepLines: true,
      children: mk(t, { size: 16, bold: hdr }),
    })],
  });
  const b = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
  const none = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  return new Table({
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    alignment: AlignmentType.CENTER,
    borders: { top: b, bottom: b, left: none, right: none, insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "999999" }, insideVertical: none },
    rows: [
      new TableRow({ tableHeader: true, cantSplit: true, children: headers.map((h, i) => cell(h, widths[i], true, i)) }),
      ...rows.map(r => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, widths[i], false, i)) })),
    ],
  });
}

// Placeholder box for a result section left blank
function blank(lines) {
  const b = { style: BorderStyle.DASHED, size: 6, color: "888888" };
  return new Table({
    width: { size: COL_W, type: WidthType.DXA }, columnWidths: [COL_W],
    borders: { top: b, bottom: b, left: b, right: b, insideHorizontal: b, insideVertical: b },
    rows: [new TableRow({ children: [new TableCell({
      width: { size: COL_W, type: WidthType.DXA },
      margins: { top: 120, bottom: 120, left: 120, right: 120 },
      shading: { type: ShadingType.CLEAR, fill: "F7F7F7", color: "auto" },
      children: lines.map(l => new Paragraph({ spacing: { after: 60 }, children: mk(l, { size: 18, italics: true }) })),
    })] })],
  });
}

const spacer = (h = 60) => new Paragraph({ spacing: { after: h }, children: [] });

