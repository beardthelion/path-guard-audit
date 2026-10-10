declare const app: any;
declare const res: any;
declare const req: any;

app.get("/file", (req: any, res: any) => {
  return res.sendFile(req.query.path);
});
