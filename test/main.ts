import { AuthClient } from "../src/auth-client";

const client = new AuthClient({
  dbname: 'auth_server',
  user: 'root',
  password: '2v&kJe^jf%!&jG>WiwieFReVLEeydmqGWV.o)mvp83W7,mz]rrv!rq3!C7hL6o+h',
});

const main = async () => {
  await client.Start();
  await client.Connect();

  return;
}

main().finally(() => {
  if (client.pool) {
    client.pool.end();
  }
});


