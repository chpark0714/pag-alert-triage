// Builds the v2 manuscript. Concatenates the shared layout helpers with the v2
// content into one module, then assembles the two-column IEEE document.
const fs = require("fs");
const path = require("path");

const HEADER = `const {
  Document, Packer, Paragraph, TextRun, AlignmentType, HeadingLevel,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  ImageRun, SectionType, LineRuleType, TabStopType, VerticalAlign,
} = require("docx");
`;

const helpers = fs.readFileSync(path.join(__dirname, "_helpers.js"), "utf8")
  .replace(/^[\s\S]*?} = require\("docx"\);/, "");
const content = fs.readFileSync(path.join(__dirname, "content_v13_short.js"), "utf8");

const EXPORTS = `
module.exports = { TITLE, authorsBlock, abstractPara, indexTerms, intro, related,
  threat, method, design, pilot, results, discussion, limits, conclusion, ack, refs, appendix };
`;

const combined = path.join(__dirname, "_combined_v13.js");
fs.writeFileSync(combined, HEADER + helpers + "\n" + content + EXPORTS);

const {
  Document, Packer, Paragraph, TextRun, AlignmentType,
  SectionType, TabStopType,
} = require("docx");
const C = require(combined);

const PAGE = { width: 11906, height: 16838 };  // A4
const MARGIN = { top: 1077, bottom: 2438, left: 812, right: 812 };  // IEEE A4: 19/43/14.32 mm
const FONT = "Times New Roman";

const doc = new Document({
  creator: "Chol",
  title: C.TITLE,
  styles: { default: { document: { run: { font: FONT, size: 20 } } } },
  sections: [
    { properties: { page: { size: PAGE, margin: MARGIN } }, children: [...C.authorsBlock] },
    {
      properties: {
        type: SectionType.CONTINUOUS,
        page: { size: PAGE, margin: MARGIN },
        column: { count: 2, space: 360, equalWidth: true },
      },
      children: [
        C.abstractPara, C.indexTerms,
        ...C.intro, ...C.related, ...C.threat, ...C.method,
        ...C.design, ...C.pilot, ...C.results, ...C.discussion,
        ...C.limits, ...C.conclusion, ...C.ack,
        new Paragraph({
          alignment: AlignmentType.CENTER, keepNext: true,
          spacing: { before: 200, after: 80 },
          children: [new TextRun({ text: "REFERENCES", font: FONT, size: 20 })],
        }),
        ...C.refs.map((t, i) => new Paragraph({
          alignment: AlignmentType.JUSTIFIED,
          spacing: { after: 40 },
          indent: { left: 360, hanging: 360 },
          tabStops: [{ type: TabStopType.LEFT, position: 360 }],
          children: [
            new TextRun({ text: `[${i + 1}]\t`, font: FONT, size: 16 }),
            new TextRun({ text: t, font: FONT, size: 16 }),
          ],
        })),
        ...C.appendix,
      ],
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(path.join(__dirname, "PAG_paper_ICCA26_short.docx"), buf);
  fs.unlinkSync(combined);
  console.log("wrote PAG_paper_ICCA26_short.docx", buf.length, "bytes");
});
