import { serialize, parse } from "cookie";
import { NextApiResponse, NextApiRequest } from "next";

export class Cookie<T> {
  static EIGHT_HOURS = 60 * 60 * 8;
  constructor(public name: string, public maxAge: number) {}

  set(res: NextApiResponse, data: T) {
    const cookie = serialize(this.name, JSON.stringify(data), {
      maxAge: this.maxAge,
      expires: new Date(Date.now() + this.maxAge * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      path: "/",
      sameSite: "lax",
    });
    res.setHeader("Set-Cookie", cookie);
  }

  remove(res: NextApiResponse) {
    const cookie = serialize(this.name, "", {
      maxAge: -1,
      path: "/",
    });

    res.setHeader("Set-Cookie", cookie);
  }

  get(req: NextApiRequest): T | undefined {
    const cookies = Cookie.parse(req);
    console.log(cookies);
    const cookieAtName = cookies[this.name];
    if (cookieAtName) return JSON.parse(cookieAtName);
    else return undefined;
  }

  static parse(req: NextApiRequest) {
    // For API Routes we don't need to parse the cookies.
    if (req.cookies) return req.cookies;

    // For pages we do need to parse the cookies.
    const cookie = req.headers?.cookie;
    return parse(cookie || "");
  }
}
