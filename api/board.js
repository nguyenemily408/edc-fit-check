import board from '../lib/board.js';
import storage from '../lib/storage.js';

const routes = new Set(['home', 'join', 'idea', 'deadline', 'inspo', 'remove-photo', 'vote', 'admin']);

export default {
  fetch(request) {
    const url = new URL(request.url);
    const route = url.searchParams.get('boardRoute') ?? 'home';
    if (!routes.has(route)) return new Response('Page not found.', {status:404});
    url.searchParams.delete('boardRoute');
    url.pathname = route === 'home' ? '/' : '/'+route;
    return board.fetch(new Request(url, request), storage);
  }
};
