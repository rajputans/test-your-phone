export function analyzeCookies(setCookie) {
  if (!setCookie) {
    return {
      checked: true, count: 0,
      secureCount: null, httpOnlyCount: null, sameSiteCount: null,
      allSecure: null, allHttpOnly: null, allSameSite: null,
    };
  }
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  const flags = cookies.map((cookie) => ({
    secure: /(?:^|;)\s*secure(?:;|$)/i.test(cookie),
    httpOnly: /(?:^|;)\s*httponly(?:;|$)/i.test(cookie),
    sameSite: /(?:^|;)\s*samesite=/i.test(cookie),
  }));
  return {
    checked: true,
    count: flags.length,
    secureCount: flags.filter((cookie) => cookie.secure).length,
    httpOnlyCount: flags.filter((cookie) => cookie.httpOnly).length,
    sameSiteCount: flags.filter((cookie) => cookie.sameSite).length,
    allSecure: flags.every((cookie) => cookie.secure),
    allHttpOnly: flags.every((cookie) => cookie.httpOnly),
    allSameSite: flags.every((cookie) => cookie.sameSite),
  };
}
