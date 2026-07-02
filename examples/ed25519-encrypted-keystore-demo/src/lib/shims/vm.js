export function runInThisContext() {
  throw new Error('vm.runInThisContext is unavailable in browser builds');
}

export default {
  runInThisContext,
};
