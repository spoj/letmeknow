// A doc's editor: markdown in CodeMirror, bound to the doc's Yjs text, which edits here and the copy the doc kind's
// in-page plugin keeps (lmk_kind_doc::Page, through its commands) keep in step. It reads as written text: headings by
// size, markdown's marks faint where they stand, list items hanging under their bullets, which show as dots, and "- [ ]"
// items as checkboxes that tick with a click; a toolbar (and Alt+↑/↓, Tab, Shift+Tab) moves and indents lines. Links
// show as their text, and open on a click, except while the cursor is in them. Images the doc links show below their
// line; pasting or dropping a file uploads it and inserts its link.
import { defaultKeymap, indentLess, indentMore, indentWithTab, moveLineDown, moveLineUp } from "@codemirror/commands";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
import { HighlightStyle, syntaxHighlighting, syntaxTree } from "@codemirror/language";
import { EditorState, type Range, StateField } from "@codemirror/state";
import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate, WidgetType, keymap, placeholder, showPanel } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { yCollab, yUndoManagerKeymap } from "y-codemirror.next";
import * as Y from "yjs";
import type { Session } from "./client";

class Checkbox extends WidgetType {
  constructor(readonly checked: boolean) {
    super();
  }

  eq(other: Checkbox) {
    return other.checked === this.checked;
  }

  toDOM() {
    return Object.assign(document.createElement("input"), { type: "checkbox", checked: this.checked, className: "cm-task" });
  }

  ignoreEvent() {
    return false;
  }
}

class Dot extends WidgetType {
  eq() {
    return true;
  }

  toDOM() {
    return Object.assign(document.createElement("span"), { className: "cm-dot" });
  }
}

/** The width of a character of a list item's indent or marker, in em: wider than most, so that lists line up in any font. */
const CHAR = 0.6;

/**
 * List items as in written lists: an item's indent and marker take a set width a character, so that its wrapped lines
 * start under its text. A bullet shows as a dot, and a task's checkbox, which ticks with a click, takes its bullet's place.
 */
function items(view: EditorView): DecorationSet {
  const { state } = view;
  const found: Range<Decoration>[] = [];
  const width = (chars: number) => ({ style: `display: inline-block; min-width: ${chars * CHAR}em; text-indent: 0` });
  for (const { from, to } of view.visibleRanges) {
    syntaxTree(state).iterate({
      from,
      to,
      enter: node => {
        if (node.name === "TaskMarker") {
          found.push(Decoration.replace({ widget: new Checkbox(state.sliceDoc(node.from + 1, node.to - 1) !== " ") }).range(node.from, node.to));
        }
        if (node.name !== "ListMark") return;
        const line = state.doc.lineAt(node.from);
        const task = /^ \[[ xX]\] /.test(state.sliceDoc(node.to, node.to + 5));
        const marker = task ? 3 : node.to - node.from + 1;
        const indent = state.sliceDoc(line.from, node.from).replace(/\t/g, "    ").length;
        const hang = (indent + marker) * CHAR;
        found.push(Decoration.line({ attributes: { style: `padding-left: calc(var(--s4) + ${hang}em); text-indent: -${hang}em` } }).range(line.from));
        if (indent) found.push(Decoration.mark({ attributes: width(indent) }).range(line.from, node.from));
        // Inclusive, so that it holds the dot that starts it.
        found.push(Decoration.mark({ inclusiveStart: true, attributes: width(marker) }).range(node.from, Math.min(node.to + (task ? 5 : 1), line.to)));
        if (task) found.push(Decoration.replace({}).range(node.from, node.to + 1));
        else if (/[-*+]/.test(state.sliceDoc(node.from, node.to))) found.push(Decoration.replace({ widget: new Dot() }).range(node.from, node.to));
      }
    });
  }
  return Decoration.set(found, true);
}

const lists = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;

    constructor(view: EditorView) {
      this.decorations = items(view);
    }

    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged || syntaxTree(update.state) !== syntaxTree(update.startState)) this.decorations = items(update.view);
    }
  },
  {
    decorations: plugin => plugin.decorations,
    eventHandlers: {
      mousedown(event, view) {
        const box = event.target as HTMLElement;
        if (!box.classList.contains("cm-task")) return false;
        const at = view.posAtDOM(box) + 1;
        view.dispatch({ changes: { from: at, to: at + 1, insert: view.state.sliceDoc(at, at + 1) === " " ? "x" : " " } });
        return true;
      }
    }
  }
);

/**
 * Links: `[text](url)` shows as its text, styled as a link, unless a cursor is in it; bare URLs are links too. An image
 * the doc links (`![alt](lmk:…)`) shows only as the image below its line, unless a cursor is in its link.
 */
function links(view: EditorView): DecorationSet {
  const { state } = view;
  const found: Range<Decoration>[] = [];
  const link = (from: number, to: number, href: string) =>
    found.push(Decoration.mark({ class: "cm-link", attributes: { "data-href": href, title: href } }).range(from, to));
  for (const { from, to } of view.visibleRanges) {
    syntaxTree(state).iterate({
      from,
      to,
      enter: node => {
        if (node.name === "URL") return void link(node.from, node.to, state.sliceDoc(node.from, node.to));
        if (node.name !== "Link" && node.name !== "Image") return;
        const [open, close] = node.node.getChildren("LinkMark");
        const url = node.node.getChild("URL");
        if (!url || !close) return false;
        const href = state.sliceDoc(url.from, url.to);
        const shown = !state.selection.ranges.some(r => r.from <= node.to && r.to >= node.from);
        if (node.name === "Image") {
          if (shown && href.startsWith("lmk:")) found.push(Decoration.replace({}).range(node.from, node.to));
        } else if (close.from > open.to) {
          link(open.to, close.from, href);
          if (shown) found.push(Decoration.replace({}).range(node.from, open.to), Decoration.replace({}).range(close.from, node.to));
        }
        return false;
      }
    });
  }
  return Decoration.set(found, true);
}

/** Links, which open on a click: web and mail links in a new tab, a file the doc links as a download. */
const linking = (blobs: Blobs) =>
  ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;

      constructor(view: EditorView) {
        this.decorations = links(view);
      }

      update(update: ViewUpdate) {
        if (update.docChanged || update.viewportChanged || update.selectionSet || syntaxTree(update.state) !== syntaxTree(update.startState)) {
          this.decorations = links(update.view);
        }
      }
    },
    {
      decorations: plugin => plugin.decorations,
      eventHandlers: {
        mousedown(event) {
          const link = (event.target as HTMLElement).closest(".cm-link");
          const href = link?.getAttribute("data-href") ?? "";
          if (href.startsWith("lmk:")) blobs.open(href, link!.textContent!);
          else if (/^(https?|mailto):/i.test(href)) window.open(href, "_blank", "noopener");
          else return false;
          return true;
        }
      }
    }
  );

/** Makes each selected line a task, or ticks or unticks it if it is one. */
function task(view: EditorView): boolean {
  const lines = new Map(view.state.selection.ranges.map(r => [view.state.doc.lineAt(r.head).number, view.state.doc.lineAt(r.head)]));
  const changes = [...lines.values()].map(line => {
    const box = /^\s*[-*+] \[([ xX])\]/.exec(line.text);
    if (box) return { from: line.from + box[0].length - 2, to: line.from + box[0].length - 1, insert: box[1] === " " ? "x" : " " };
    const bullet = /^\s*[-*+] /.exec(line.text);
    return bullet ? { from: line.from + bullet[0].length, insert: "[ ] " } : { from: line.from + /^\s*/.exec(line.text)![0].length, insert: "- [ ] " };
  });
  view.dispatch({ changes });
  return true;
}

/** Buttons for what the keyboard does with lines, as phones have no Alt or Tab; they keep the editor's focus. */
function toolbar(view: EditorView): HTMLElement {
  const bar = Object.assign(document.createElement("div"), { className: "cm-tools" });
  const tools: [string, string, (view: EditorView) => boolean][] = [
    ["↑", "Move the line up (Alt+↑)", moveLineUp],
    ["↓", "Move the line down (Alt+↓)", moveLineDown],
    ["⇤", "Outdent (Shift+Tab)", indentLess],
    ["⇥", "Indent (Tab)", indentMore],
    ["☑", "Make the line a task, or tick it", task]
  ];
  for (const [label, title, run] of tools) {
    const button = Object.assign(document.createElement("button"), { type: "button", className: "quiet icon", textContent: label, title, ariaLabel: title });
    button.onpointerdown = event => event.preventDefault();
    button.onclick = () => run(view);
    bar.append(button);
  }
  return bar;
}

/**
 * How the editor reaches the files the doc links: a linked image as a data: URL, uploading a file (which gives its
 * link), and saving a linked file.
 */
export type Blobs = {
  show: (link: string) => Promise<string>;
  attach: (bytes: Uint8Array) => Promise<string>;
  open: (link: string, name: string) => void;
  fail: (error: unknown) => void;
};

const LONGEST_SIDE = 1600;

class Picture extends WidgetType {
  constructor(
    readonly link: string,
    readonly blobs: Blobs
  ) {
    super();
  }

  eq(other: Picture) {
    return other.link === this.link;
  }

  toDOM(view: EditorView) {
    const box = Object.assign(document.createElement("div"), { className: "cm-image" });
    box.style.padding = "4px 0";
    this.blobs.show(this.link).then(
      src => {
        const img = Object.assign(document.createElement("img"), { src, onload: () => view.requestMeasure() });
        Object.assign(img.style, { display: "block", maxWidth: "100%", maxHeight: "24rem" });
        box.append(img);
      },
      error => {
        box.textContent = `image unavailable: ${error instanceof Error ? error.message : error}`;
        box.style.opacity = "0.6";
      }
    );
    return box;
  }
}

function pictures(state: EditorState, blobs: Blobs): DecorationSet {
  const found: Range<Decoration>[] = [];
  for (const match of state.doc.toString().matchAll(/!\[[^\]\n]*\]\((lmk:[0-9a-f]{64}\.[0-9]+#[0-9a-f]{64})\)/g)) {
    const end = state.doc.lineAt(match.index).to;
    found.push(Decoration.widget({ widget: new Picture(match[1], blobs), block: true, side: 1 }).range(end));
  }
  return Decoration.set(found, true);
}

/** An image scaled to at most LONGEST_SIDE pixels, as WebP (JPEG where the browser cannot). */
async function shrink(file: Blob): Promise<Uint8Array> {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, LONGEST_SIDE / Math.max(bitmap.width, bitmap.height));
  const canvas = new OffscreenCanvas(Math.max(1, Math.round(bitmap.width * scale)), Math.max(1, Math.round(bitmap.height * scale)));
  canvas.getContext("2d")!.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  let encoded = await canvas.convertToBlob({ type: "image/webp", quality: 0.9 });
  if (encoded.type !== "image/webp") encoded = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.9 });
  return new Uint8Array(await encoded.arrayBuffer());
}

/**
 * Uploads `files` (images scaled down) and inserts their links on lines of their own, after the line at `at`, so that
 * a drop never splits a link; false if there are none, so the editor handles the event.
 */
function insertFiles(view: EditorView, blobs: Blobs, event: Event, files: FileList | undefined, at: number): boolean {
  if (!files?.length) return false;
  event.preventDefault();
  for (const file of files) {
    const image = /^image\/(png|jpeg|gif|webp)$/.test(file.type);
    const name = (image ? file.name.replace(/\.[^.]*$/, "") : file.name).replace(/[[\]]/g, "");
    (image ? shrink(file) : file.arrayBuffer().then(bytes => new Uint8Array(bytes)))
      .then(blobs.attach)
      .then(link => {
        const line = view.state.doc.lineAt(Math.min(at, view.state.doc.length));
        view.dispatch({ changes: { from: line.to, insert: `${line.length ? "\n" : ""}${image ? "!" : ""}[${name}](${link})` } });
      })
      .catch(blobs.fail);
  }
  return true;
}

/** From the session: an edit made elsewhere. */
const REMOTE = "lmk";

function b64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64(text: string): Uint8Array {
  return Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), char => char.charCodeAt(0));
}

/** A command of the doc kind's in-page plugin. */
const command = async (lmk: Session, ...args: string[]) => JSON.parse(await lmk.command("doc", JSON.stringify(args)));

/** An editor of the doc `gid`. `edited` takes in what the plugin's copy has that this one lacks. */
export async function bind(parent: HTMLElement, lmk: Session, gid: string, blobs: Blobs) {
  const doc = new Y.Doc();
  Y.applyUpdate(doc, unb64((await command(lmk, "state", gid)).state), REMOTE);
  doc.on("update", (update: Uint8Array, origin: unknown) => origin !== REMOTE && command(lmk, "edit", gid, b64(update)).catch(blobs.fail));
  const view = editor(parent, doc.getText("text"), blobs);
  return {
    edited: () => command(lmk, "diff", gid, b64(Y.encodeStateVector(doc))).then(({ diff }) => Y.applyUpdate(doc, unb64(diff), REMOTE), blobs.fail),
    measure: () => view.requestMeasure(),
    destroy: () => (view.destroy(), doc.destroy())
  };
}

/** Markdown as it reads: headings by their size, emphasis as it says, and faint the marks that make them. */
const reading = HighlightStyle.define([
  { tag: tags.heading1, fontSize: "1.6em", fontWeight: "600" },
  { tag: tags.heading2, fontSize: "1.35em", fontWeight: "600" },
  { tag: tags.heading3, fontSize: "1.15em", fontWeight: "600" },
  { tag: [tags.heading4, tags.heading5, tags.heading6], fontWeight: "600" },
  { tag: tags.strong, fontWeight: "600" },
  { tag: tags.emphasis, fontStyle: "italic" },
  { tag: tags.strikethrough, textDecoration: "line-through" },
  { tag: tags.monospace, fontFamily: "ui-monospace, monospace", fontSize: "0.9em" },
  { tag: [tags.processingInstruction, tags.url, tags.contentSeparator], color: "var(--muted)" }
]);

function editor(parent: HTMLElement, text: Y.Text, blobs: Blobs): EditorView {
  const extensions = [
    keymap.of([...yUndoManagerKeymap, ...defaultKeymap, indentWithTab]),
    markdown({ base: markdownLanguage }),
    linking(blobs),
    showPanel.of(view => ({ dom: toolbar(view), top: true })),
    syntaxHighlighting(reading),
    EditorView.lineWrapping,
    placeholder("Write here. Everyone in this document, people and agents, edits it at once."),
    lists,
    StateField.define<DecorationSet>({
      create: state => pictures(state, blobs),
      update: (decorations, tr) => (tr.docChanged ? pictures(tr.state, blobs) : decorations),
      provide: field => EditorView.decorations.from(field)
    }),
    EditorView.domEventHandlers({
      paste: (event, view) => insertFiles(view, blobs, event, event.clipboardData?.files, view.state.selection.main.head),
      drop: (event, view) => insertFiles(view, blobs, event, event.dataTransfer?.files, view.posAtCoords(event) ?? view.state.selection.main.head)
    }),
    yCollab(text, null)
  ];
  return new EditorView({ parent, state: EditorState.create({ doc: text.toString(), extensions }) });
}
