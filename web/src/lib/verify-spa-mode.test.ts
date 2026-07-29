/**
 * SPA-mode regression test.
 *
 * Verifies the built index.html is a classic client-side SPA shell — no RSC
 * markers, no SSR pre-rendering — confirming that RSC-specific advisories
 * (e.g. GHSA-qwww-vcr4-c8h2) do not apply to this deployment.
 *
 * NOTE: requires `npm run build` to have run first so the output exists at
 * internal/dashboard/static/dist/index.html. The first test skips all
 * remaining tests if the file is absent.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

const distIndex = resolve(
  import.meta.dirname, // web/src/lib
  '../../../internal/dashboard/static/dist/index.html',
);

let html: string;
let built = false;

beforeAll(() => {
  built = existsSync(distIndex);
  if (built) {
    html = readFileSync(distIndex, 'utf-8');
  }
});

describe('SPA mode (no RSC / no SSR)', () => {
  it('has been built (run npm run build first)', () => {
    expect(built).toBe(true);
  });

  describe('no RSC / no SSR markers', () => {
    // React Router RSC mode injects __RSC and __reactRouterServerData
    // into the HTML. Their absence confirms classic SPA delivery.
    const rscMarkers = ['__RSC', '__reactRouterServerData', 'data-rsc'];

    for (const marker of rscMarkers) {
      it(`does not contain "${marker}"`, () => {
        if (!built) return;
        expect(html).not.toContain(marker);
      });
    }
  });

  describe('classic SPA root', () => {
    // A classic SPA has an empty <div id="root"> that React hydrates.
    it('contains <div id="root"> as mount point', () => {
      if (!built) return;
      expect(html).toContain('<div id="root">');
    });

    it('has no pre-rendered content inside #root', () => {
      if (!built) return;
      const rootOpen = '<div id="root">';
      const rootIdx = html.indexOf(rootOpen);
      expect(rootIdx).not.toBe(-1);
      const afterOpen = html.slice(rootIdx + rootOpen.length);
      const contentBetween = afterOpen.slice(0, afterOpen.indexOf('</div>'));
      expect(contentBetween.trim()).toBe('');
    });
  });

  describe('no server-rendered script payloads', () => {
    it('has no inline <script> with server data', () => {
      if (!built) return;
      const inlineScripts = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi);
      if (inlineScripts) {
        for (const script of inlineScripts) {
          const inner = script
            .replace(/<script[^>]*>/, '')
            .replace('</script>', '')
            .trim();
          if (inner.length > 0) {
            expect(inner).not.toMatch(/window\.__/);
            expect(inner).not.toMatch(/serverData/);
          }
        }
      }
    });
  });
});
