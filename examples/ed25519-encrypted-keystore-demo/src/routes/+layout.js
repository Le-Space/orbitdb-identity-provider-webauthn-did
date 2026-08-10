export const prerender = true;
export const trailingSlash = 'always';
// SSR on, so prerendering actually renders the page instead of emitting a bare
// shell. With ssr = false the build produced 1.2 kB of skeleton with no <title>
// and no description at all — nothing for a search result or a link preview.
export const ssr = true;
