// Check user identity & rate limit
export async function checkQuota(req, env) {
  const url = new URL(req.url);
  const userId = url.searchParams.get("userId") || req.headers.get("x-user-id");

  if (!userId) {
    return { allowed: false, response: new Response("Missing userId", { status: 400 }) };
  }

  const allowedUsers = ["group-1", "group-2", "group-3"];
  if (!allowedUsers.includes(userId)) {
    return { allowed: false, response: new Response("Forbidden", { status: 403 }) };
  }

  // // ---- Daily quota check ----
  // const today = new Date().toISOString().slice(0, 10);
  // const key = `${userId}:${today}`;
  // let count = parseInt(await env.USER_KV.get(key)) || 0;

  // if (count >= 16600) {
  //   return {
  //     allowed: false,
  //     response: new Response("429 Daily quota exceeded", { status: 429 })
  //   };
  // }

  // await env.USER_KV.put(key, (count + 1).toString(), { expirationTtl: 86400 });

  // ---- Per-minute rate limit ----
  const { success } = await env.USER_RATE_LIMITER.limit({ key: userId });
  if (!success) {
    return {
      allowed: false,
      response: new Response("430 Too Many Requests - per minute", { status: 430 })
    };
  }

  return { allowed: true, userId };
}
