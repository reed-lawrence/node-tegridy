import { createPool } from "mysql";
import { AuthClient } from "../src/auth-client";

const client = new AuthClient({
  database: 'myApp',
  host: 'localhost',
  user: 'root',
  port: 3306,
  password: '2v&kJe^jf%!&jG>WiwieFReVLEeydmqGWV.o)mvp83W7,mz]rrv!rq3!C7hL6o+h',
});

const main = async () => {
  const token = await client.RequestForgeryToken();
  console.log(token);
  return;
}

main().finally(() => {
  client.pool.end();
});



