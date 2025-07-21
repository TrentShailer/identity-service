export async function setHref(target: string): Promise<never> {
  location.href = target;
  return await block();
}

function block(): Promise<never> {
  // deno-lint-ignore no-explicit-any
  const poll = (resolve: any) => {
    setTimeout(() => poll(resolve), 400);
  };

  return new Promise(poll);
}
