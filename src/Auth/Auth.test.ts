import Auth from "./Auth";

test("init", () => {
  const users = [];
  const auth = new Auth<any>({
    findUserAction: async (username: string) => {
      return users[0];
    },
    createUserAction: async (userData: { hash: string; salt: string }) => {
      users.push(userData);
      return true;
    },
    token: {
      name: "token",
      maxAge: 60 * 60 * 24,
      secret: "secret",
    },
  });
});
