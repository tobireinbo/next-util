import crypto from "crypto";
import Iron from "@hapi/iron";
import { NextApiRequest, NextApiResponse } from "next";

import passport from "passport";
import Local from "passport-local";
import nextConnect from "next-connect";
import { Cookie } from "..";

type FindUserAction<User> = (username: string) => Promise<User>;
type CreateUserAction<User> = (user: User) => Promise<boolean>;

export default class Auth<T> {
  private _findUserAction: (username: string) => Promise<T>;
  private _createUserAction: (userData: T) => Promise<boolean>;
  private _tokenCookie: Cookie<string>;
  private _tokenSecret: string;

  constructor(args: {
    findUserAction: FindUserAction<T>;
    createUserAction: CreateUserAction<T>;
    token: { name: string; maxAge: number; secret: string };
  }) {
    this._findUserAction = args.findUserAction;
    this._createUserAction = args.createUserAction;
    this._tokenCookie = new Cookie<string>(args.token.name, args.token.maxAge);
    this._tokenSecret = args.token.secret;
  }

  logout(req: NextApiRequest, res: NextApiResponse) {
    this._tokenCookie.remove(res);
    res.writeHead(302, { Location: "/" });
    res.end();
  }

  async signup(req: NextApiRequest, res: NextApiResponse) {
    try {
      await this._createUserAction(req.body);
      res.status(200).send({ done: true });
    } catch (error: any) {
      console.error(error);
      res.status(500).end(error.message);
    }
  }

  login() {
    passport.use(
      new Local.Strategy(function (username: string, password: string, done) {
        this.findUserAction(username)
          .then((user) => {
            if (user && Auth.validatePassword(user, password)) {
              done(null, user);
            } else {
              done(new Error("Invalid username and password combination"));
            }
          })
          .catch((error) => {
            done(error);
          });
      })
    );

    const authenticate = (
      method: string,
      req: NextApiRequest,
      res: NextApiResponse
    ) =>
      new Promise<any>((resolve, reject) => {
        passport.authenticate(method, { session: false }, (error, token) => {
          if (error) {
            reject(error);
          } else {
            resolve(token);
          }
        })(req, res);
      });

    return nextConnect()
      .use(passport.initialize())
      .post(async (req: NextApiRequest, res: NextApiResponse) => {
        try {
          const user = await authenticate("local", req, res);
          // session is the payload to save in the token, it may contain basic info about the user
          const session = { ...user };

          await this.setLoginSession(res, session);

          res.status(200).send({ done: true });
        } catch (error: any) {
          console.error(error);
          res.status(401).send(error.message);
        }
      });
  }

  async user(req: NextApiRequest, res: NextApiResponse) {
    try {
      const session = await this.getLoginSession(req);
      const user = (session && (await this._findUserAction(session))) ?? null;

      res.status(200).json({ user });
    } catch (error) {
      console.error(error);
      res.status(500).end("Authentication token is invalid, please log in");
    }
  }

  static validatePassword(
    userData: { salt: string; hash: string },
    inputPassword: crypto.BinaryLike
  ) {
    const inputHash = crypto
      .pbkdf2Sync(inputPassword, userData.salt, 1000, 64, "sha512")
      .toString("hex");
    const passwordsMatch = userData.hash === inputHash;
    return passwordsMatch;
  }

  private async setLoginSession(res: NextApiResponse, session: any) {
    const createdAt = Date.now();
    // Create a session object with a max age that we can validate later
    const obj = { ...session, createdAt, maxAge: this._tokenCookie.maxAge };
    const token = await Iron.seal(obj, this._tokenSecret, Iron.defaults);

    this._tokenCookie.set(res, token);
  }

  private async getLoginSession(req: NextApiRequest) {
    const token = this._tokenCookie.get(req);

    if (!token) return;

    const session = await Iron.unseal(token, this._tokenSecret, Iron.defaults);
    const expiresAt = session.createdAt + session.maxAge * 1000;

    // Validate the expiration date of the session
    if (Date.now() > expiresAt) {
      throw new Error("Session expired");
    }

    return session;
  }
}
