import express from 'express';
import morgan from 'morgan';

const app = express();
app.use(morgan('dev'));
app.use(express.static('public'));

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`UI server listening on http://localhost:${port}`);
});