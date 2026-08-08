Deno.serve(async (req: Request) => {
  return new Response(JSON.stringify({ 
    success: true, 
    message: "Authentication removed. Open access.",
    token: "open"
  }), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
});
