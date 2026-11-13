import { createHash, timingSafeEqual } from 'node:crypto';
import { firstName, rankOutfits, topOutfits, votingPhase } from './voting.js';

const ADMIN_SESSION_SALT = process.env.EDC_ADMIN_SESSION_SALT;
const ADMIN_VERIFY = Buffer.from(process.env.EDC_ADMIN_VERIFY ?? '', 'hex');
const ADMIN_COOKIE = '__Host-edc_admin';
const INVITE = process.env.EDC_INVITE_HASH;
const SHORT_INVITE = process.env.EDC_SHORT_INVITE_HASH;
const COOKIE = '__Host-edc_access';
const VOTER_COOKIE = '__Host-edc_voter';
const VIEWER_COOKIE = '__Host-edc_viewer';
const invitePattern = /^[A-Za-z0-9_-]{32}$/;
const shortInvitePattern = /^[A-Za-z0-9_-]{12}$/;
const PHOTO_BATCH_SIZE = 3;
const PHOTO_BASE64_LIMIT = 400000;
const PHOTO_TYPE = 'image/jpeg';
const photoIdPattern = /^[0-9a-f-]{36}$/;
const validPhotoKey = key => photoIdPattern.test(key) || /^(0|[1-9]\d{0,5})$/.test(key);
const photoHeaders = {
  'Content-Type': PHOTO_TYPE,
  'Content-Security-Policy': "default-src 'none'; sandbox",
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'private, no-store',
  'Cross-Origin-Resource-Policy': 'same-origin'
};

async function roleFor(key) {
  const isShortInvite = shortInvitePattern.test(key ?? '');
  if (!isShortInvite && !invitePattern.test(key ?? '')) return '';
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  const hash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2,'0')).join('');
  if (isShortInvite) return hash === SHORT_INVITE ? 'friend' : '';
  return hash === INVITE ? 'friend' : '';
}

const digest = value => createHash('sha256').update(value).digest('hex');
function validAdminSession(session) {
  return Boolean(ADMIN_SESSION_SALT) && ADMIN_VERIFY.length === 32 &&
    /^[a-f0-9]{64}$/.test(session ?? '') &&
    timingSafeEqual(Buffer.from(digest('edc-admin-verify:'+session), 'hex'), ADMIN_VERIFY);
}

const safe = (s='') => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const deadlineText = timestamp => new Intl.DateTimeFormat('en-SG', {
  dateStyle:'full',timeStyle:'short',timeZone:'Asia/Singapore'
}).format(timestamp);
const toInput = timestamp => new Date(timestamp + 28800000).toISOString().slice(0,16);
const headers = {
  'Cache-Control':'no-store, private','Referrer-Policy':'same-origin','X-Robots-Tag':'noindex, nofollow',
  'X-Content-Type-Options':'nosniff',
  'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' blob:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
};
function html(body,status=200) {
  return new Response(body,{status,headers:{...headers,'Content-Type':'text/html; charset=utf-8'}});
}
function redirect(path='/',extra={}) {
  return new Response(null,{status:303,headers:{...headers,Location:path,...extra}});
}
function joinBoard(key, destination='/') {
  return redirect(destination, {'Set-Cookie':COOKIE+'='+key+'; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=15552000'});
}
function joinBallot(key) {
  return redirect('/vote#voting', {'Set-Cookie':VOTER_COOKIE+'='+key+'; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=15552000'});
}
const deadlineSavedMessage = 'Submission deadline saved.';

function validPhoto(photo) {
  if (typeof photo !== 'string' || photo.length > PHOTO_BASE64_LIMIT ||
      !/^\/9j\/[A-Za-z0-9+/]*={0,2}$/.test(photo) || photo.length % 4 !== 0) return false;
  const tail = atob(photo.slice(-8));
  return tail.endsWith(String.fromCharCode(255, 217));
}

function renderBoard({deadline, ideas, voting}, role, options={}) {
  const closed = Boolean(deadline && deadline <= Date.now());
  return html(page({role,deadline,ideas,closed,voting,...options}), options.error ? 400 : 200);
}

export default {
  async fetch(request, storage) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cookies = request.headers.get('Cookie')?.split(/;\s*/) ?? [];
    const cookie = name => cookies.find(value => value.startsWith(name+'='))?.slice(name.length+1);
    const role = validAdminSession(cookie(ADMIN_COOKIE)) ? 'organizer' : await roleFor(cookie(COOKIE));
    const voterKey = cookie(VOTER_COOKIE);
    const wantsJson = request.headers.get('Accept') === 'application/json';
    let snapshot;
    const read = () => snapshot ??= storage.read();
    const findVoter = async () => invitePattern.test(voterKey ?? '')
      ? (await read()).voting?.voters.find(voter => voter.key === voterKey)
      : undefined;
    const findViewer = async () => {
      const viewerKey = cookie(VIEWER_COOKIE);
      if (!/^[a-f0-9]{64}$/.test(viewerKey ?? '')) return undefined;
      return (await read()).voting?.voters.find(voter => digest('edc-viewer:'+voter.key) === viewerKey);
    };
    try {
      if (path === '/admin' && request.method === 'GET') {
        if (url.searchParams.get('view') === 'rankings') {
          if (role !== 'organizer') return new Response(null, {status:403,headers});
          const {ideas, voting} = await read();
          return html(renderAdminRankings(ideas, voting));
        }
        return role === 'organizer'
          ? renderBoard(await read(), role, {manageView:true})
          : html(page({adminView:true, voteView:true}));
      }
      if (path === '/join' && request.method === 'GET') {
        const key = url.searchParams.get('guest');
        if (!shortInvitePattern.test(key ?? '') || await roleFor(key) !== 'friend') {
          return html(page({}), 404);
        }
        const destination = url.searchParams.get('vote') === '1' ? '/vote#voting' : '/';
        return role === 'organizer' ? redirect(destination) : joinBoard(key, destination);
      }
      if (path === '/inspo' && request.method === 'GET') {
        if (role !== 'organizer' && !await findVoter() && !await findViewer()) return new Response('Voter access required.', {status:403,headers});
        const id = url.searchParams.get('id') ?? '';
        const file = url.searchParams.get('file') ?? url.searchParams.get('slot') ?? '';
        if (!photoIdPattern.test(id) || !validPhotoKey(file)) {
          return new Response('Photo not found.', {status:404,headers});
        }
        const photo = await storage.getPhoto(id, file);
        if (!photo) return new Response('Photo not found.', {status:404,headers});
        return new Response(photo, {headers:photoHeaders});
      }
      if (request.method === 'POST') {
        const origin = request.headers.get('Origin');
        // An already-open form may still use the previous no-referrer policy.
        const fromOlderForm = (origin === null || origin === 'null') &&
          request.headers.get('Sec-Fetch-Site') === 'same-origin';
        if (origin !== url.origin && !fromOlderForm) {
          return new Response('Open the board to make changes.', {status:403,headers});
        }
        if (path === '/admin') {
          const data = await request.formData();
          const attributes = '; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=';
          if (data.get('action') === 'signout') {
            return redirect('/admin', {'Set-Cookie':ADMIN_COOKIE+'='+attributes+'0'});
          }
          const password = data.get('password');
          if (typeof password === 'string' && password.length > 0 && password.length <= 128) {
            const session = digest('edc-admin-session:'+ADMIN_SESSION_SALT+':'+password);
            if (validAdminSession(session)) {
              return redirect('/admin', {'Set-Cookie':ADMIN_COOKIE+'='+session+attributes+'43200'});
            }
          }
          return html(page({adminView:true, voteView:true,error:'Incorrect admin password.'}), 403);
        }
        if (path === '/join') {
          const data = await request.formData();
          const invite = data.get('key');
          const newRole = await roleFor(invite);
          if (!newRole) return new Response('Invalid invite',{status:403,headers});
          if (role !== 'organizer') {
            return joinBoard(invite);
          }
          return redirect();
        }
        if (path === '/vote') {
          const data = await request.formData();
          const action = data.get('action');
          if (action === 'join') {
            const key = String(data.get('key') ?? '');
            if (!invitePattern.test(key) || !(await read()).voting?.voters.some(voter => voter.key === key)) {
              return new Response('Invalid voting link.', {status:403,headers});
            }
            return joinBallot(key);
          }
          const votingError = async error => {
            const voter = await findVoter();
            return renderBoard(await read(), role || 'visitor', {voter,error,voteView:true,nameGate:!voter && ['ballot','register'].includes(action),manageView:role === 'organizer' && !['ballot','register'].includes(action)});
          };
          if (action === 'register') {
            if (await findVoter()) return redirect('/vote#voting');
            const name = String(data.get('name') ?? '').trim().replace(/\s+/g, ' ');
            if (!name || name.length > 80) return await votingError('Enter your name, up to 80 characters.');
            const board = await read();
            const voter = storage.findRosterVoter(board, name);
            if (!voter) return await votingError('That name isn’t on the voter list. Check your first name or contact the host.');
            const phase = votingPhase(board.voting);
            if (voter.ballot || phase === 'closed') {
              const viewerKey = digest('edc-viewer:'+voter.key);
              return redirect('/', {'Set-Cookie':VIEWER_COOKIE+'='+viewerKey+'; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=15552000'});
            }
            if (phase !== 'open') return await votingError('Voting is unavailable right now.');
            return joinBallot(voter.key);
          }
          if (action === 'ballot') {
            const picks = ['first','second','third'].map(rank => String(data.get(rank) ?? ''));
            if (!await findVoter()) return await votingError('Enter your name to start voting.');
            if (!await storage.submitBallot(voterKey, picks)) {
              return await votingError('The ballot could not be saved. Check that voting is open, choose three different outfits, and check whether you already voted.');
            }
            return redirect('/vote#voting');
          }
          if (role !== 'organizer') return new Response('Organizer access required.', {status:403,headers});
          if (action === 'roster') {
            const names = String(data.get('names') ?? '').split(/\r?\n/).map(name => name.trim()).filter(Boolean);
            if (!names.length || names.length > 250 || names.some(name => name.length > 80)) {
              return await votingError('Enter one name per line, up to 80 characters per name.');
            }
            if (!await storage.addVoters(names)) return await votingError('The roster is full or voting has closed.');
          } else if (action === 'open') {
            if (!await storage.startVoting()) return await votingError('Voting can open after submissions close, once there are at least three outfits.');
          } else if (action === 'close') {
            if (!await storage.closeVoting()) return await votingError('Voting has to be open before you can close it.');
          } else {
            return new Response('Page not found.', {status:404,headers});
          }
          return redirect('/admin');
        }
        const voter = await findVoter();
        if (!role && !voter) return html(page({}),403);
        const data = await request.formData();
        const fail = async (error, fields={}) => wantsJson
          ? Response.json({error}, {status:400,headers})
          : renderBoard(await storage.read(), role || 'voter', {voter,error,fields,ideaView:path === '/idea'});
        if (path === '/idea') {
          const fields = Object.fromEntries(['title','author','notes','link'].map(k => [k,String(data.get(k) ?? '').trim()]));
          const {title,author,notes,link} = fields;
          if (!title || title.length > 80 || !author || author.length > 40 || notes.length > 500 || link.length > 1000) {
            return fail('Add an outfit name and your name, and check the field limits.',fields);
          }
          if (link) {
            let parsed;
            try { parsed = new URL(link); } catch {}
            if (!parsed || !['http:','https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
              return fail('Enter a link that begins with https:// or http://.',fields);
            }
          }
          const photos = data.getAll('photo');
          if (photos.length > PHOTO_BATCH_SIZE || !photos.every(validPhoto)) {
            return fail('Choose up to three photos and try again.', fields);
          }
          const id = await storage.addIdea({title, author, notes, link}, photos);
          if (!id) return await fail('This board is no longer accepting new ideas.');
          return wantsJson ? Response.json({id}, {headers}) : redirect('/#idea-'+id);
        }
        if (path === '/inspo') {
          const id = String(data.get('idea') ?? '');
          const photos = data.getAll('photo');
          if (!photoIdPattern.test(id) || !photos.length || photos.length > PHOTO_BATCH_SIZE || !photos.every(validPhoto)) {
            return await fail('Choose at least one photo and try again.');
          }
          if (!await storage.addPhotos(id, photos)) {
            return await fail('These photos couldn’t be added. The idea may be missing or submissions may have closed.');
          }
          return wantsJson
            ? Response.json({added:photos.length}, {headers})
            : redirect('/?photoIdea='+id+'&photoAdded='+photos.length+'#idea-'+id);
        }
        if (path === '/remove-photo') {
          if (role !== 'organizer') return new Response('Only the organizer can remove photos.', {status:403,headers});
          const id = String(data.get('idea') ?? '');
          const file = String(data.get('file') ?? '');
          if (!photoIdPattern.test(id) || !validPhotoKey(file)) return await fail('This photo couldn’t be found.');
          await storage.removePhoto(id, file);
          return redirect('/#idea-'+id);
        }
        if (path === '/deadline') {
          if (role !== 'organizer') return new Response('Only the organizer can set the deadline.',{status:403,headers});
          const input = String(data.get('deadline') ?? '');
          const now = Date.now();
          const deadline = Date.parse(input+'+08:00');
          if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(input) || !Number.isFinite(deadline) || toInput(deadline) !== input || deadline <= now) {
            return fail('Choose a date and time in the future.',{deadline:input});
          }
          const saved = await storage.setDeadline(deadline);
          if (!saved) return fail('The submission deadline has already passed or the new time is no longer in the future.');
          return redirect('/?saved=deadline#settings');
        }
      }
      if ((path === '/' || path === '/vote' || path === '/idea') && request.method === 'GET') {
        if (url.searchParams.get('view') === 'manage') return redirect('/admin');
        const voter = await findVoter();
        const viewer = !voter && await findViewer();
        const nameGate = !voter && !viewer && (role !== 'organizer' || path === '/vote');
        if (path === '/idea' && nameGate) return redirect('/');
        const saved = url.searchParams.get('saved');
        const options = {
          notice:saved === 'deadline' ? deadlineSavedMessage : '',
          voter,
          ideaView:path === '/idea',
          voteView:path === '/vote' || nameGate,
          nameGate,
          alreadyVoted:Boolean(viewer?.ballot),
          photoIdea:url.searchParams.get('photoIdea'),
          photoAdded:Number(url.searchParams.get('photoAdded')),
        };
        return renderBoard(await read(), role || (voter ? 'voter' : 'visitor'), options);
      }
      return new Response('Page not found.',{status:404,headers});
    } catch(e) {
      console.error('Board request failed', e?.message);
      return wantsJson
        ? Response.json({error:'The board couldn’t save the update. Try again.'}, {status:503,headers})
        : html(page({unavailable:true}),503);
    }
  }
};

function page({role='', deadline, ideas=[], closed=false, error='', fields={}, notice='', photoIdea='', photoAdded=0, unavailable=false, personalLink=false, voting, voter, manageView=false, ideaView=false, voteView=false, nameGate=false, adminView=false, alreadyVoted=false}) {
  const phase = votingPhase(voting);
  const votingActive = phase === 'open' || phase === 'closed';
  const boardView = Boolean(role && !manageView && !ideaView && !nameGate && !adminView);
  const canRank = phase === 'open' && voter && !voter.ballot && !manageView && !ideaView;
  const list = ideas.map(({id,title,notes,link,photoCount=0,photoKeys=[]})=>{
    const photos = Array.from({length:photoCount}, (_,slot)=>{
      const key = photoKeys[slot] ?? String(slot);
      const src = '/inspo?id='+safe(id)+'&amp;file='+safe(key);
      const label = 'Inspiration photo '+(slot+1)+' for '+safe(title);
      return `<div class="idea-photo">
        <a href="${src}" target="_blank" rel="noopener"><img src="${src}" alt="${label}" loading="lazy"><span class="photo-hover" aria-hidden="true"><img src="${src}" alt="" loading="lazy"></span></a>
        ${role === 'organizer' ? `<form class="remove-photo" hidden action="/remove-photo" method="post" onsubmit="return confirm('Remove this photo from the board?')">
          <input type="hidden" name="idea" value="${safe(id)}">
          <input type="hidden" name="file" value="${safe(key)}">
          <button type="submit" title="Remove photo" aria-label="Remove ${label}"><span aria-hidden="true">×</span></button>
        </form>` : ''}
      </div>`;
    }).join('');
    return `
    <li class="idea" id="idea-${safe(id)}"><div class="idea-copy">
    <h3>${safe(title)}</h3>
    ${notes ? '<p class="notes">'+safe(notes)+'</p>' : ''}
    ${link ? '<a href="'+safe(link)+'" target="_blank" rel="noopener noreferrer">Open inspiration ↗</a>' : ''}
    ${photoIdea === id && Number.isInteger(photoAdded) && photoAdded >= 1 && photoAdded <= photoCount ? `<p class="photo-added" role="status">${photoAdded === 1 ? 'Photo added.' : photoAdded+' photos added.'}</p>` : ''}
    </div>
    <div class="idea-photos">${photos}
      ${!closed && role !== 'visitor' ? `<button type="button" class="photo-plus" data-idea="${safe(id)}" data-title="${safe(title)}" aria-label="Add photos to ${safe(title)}" title="Add photos"><span aria-hidden="true">+</span></button>` : ''}
    </div>${canRank ? `<button class="rank-pick" type="button" data-pick="${safe(id)}" aria-pressed="false" aria-label="Pick ${safe(title)}">Pick</button>` : ''}
    </li>`;
  }).join('');
  const outfitBoard = `<div class="board${canRank ? ' rank-board' : ''}"><section class="panel" id="ideas" aria-labelledby="outfit-ideas-heading"><div class="head"><div><h2 id="outfit-ideas-heading">Outfit ideas</h2><p class="hint">${ideas.length} ${ideas.length===1 ? 'idea' : 'ideas'} on the board</p></div><div class="board-status">
    <span class="status ${closed ? 'off' : ''}">${closed ? 'Closed' : 'Open'}</span>
    ${role === 'organizer' && ideas.some(idea => idea.photoCount > 0) ? '<button class="photo-edit" type="button" aria-expanded="false" aria-controls="idea-list">Edit photos</button>' : ''}
  </div></div>
  <p class="deadline">${deadline ? (closed ? 'Submissions closed ' : 'Submissions close ')+safe(deadlineText(deadline))+' (Singapore time).' : 'The organizer hasn’t set a deadline yet.'}</p>
  ${list ? '<ol class="ideas" id="idea-list">'+list+'</ol>' : '<div class="empty"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 1c1 8 6 13 15 15-9 2-14 7-15 15C15 23 10 18 1 16 10 14 15 9 16 1Z" fill="currentColor"/></svg><strong>No looks on the board yet</strong><p>'+ (closed ? 'The idea round has ended.' : 'Add the first outfit idea to get things started.') +'</p></div>'}</section>
  <dialog class="panel full-photo" id="full-photo" aria-labelledby="full-photo-title">
    <div class="head"><h2 id="full-photo-title">Inspiration photo</h2><form method="dialog"><button autofocus>Close</button></form></div>
    <img alt="">
  </dialog>
  ${canRank ? rankControls : ''}
  <script>
    (() => {
      const list = document.getElementById('idea-list');
      const dialog = document.getElementById('full-photo');
      if (!list || typeof dialog.showModal !== 'function') return;
      const title = dialog.querySelector('h2');
      const image = dialog.querySelector('img');
      list.addEventListener('click', event => {
        const photo = event.target.closest('.idea-photo > a');
        if (!photo || event.button !== 0 || event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return;
        event.preventDefault();
        title.textContent = photo.querySelector('img').alt;
        image.alt = title.textContent;
        image.src = photo.href;
        dialog.showModal();
      });
    })();
  </script>
  ${!closed ? `<dialog class="panel photo-dialog" id="photo-dialog" aria-labelledby="photo-dialog-title">
    <h2 id="photo-dialog-title">Add inspiration photos</h2>
    <p class="hint" id="photo-dialog-idea"></p>
    <form data-photo-form data-required action="/inspo" method="post">
      <input type="hidden" name="idea">
      ${photoPicker('extra-photos', 'Choose photos together or one at a time')}
      <div class="photo-dialog-actions"><button type="submit" disabled>Save photos</button>
      <button class="photo-cancel" type="button">Cancel</button></div>
    </form>
  </dialog><script>${photoFormScript}</script>` : ''}
  </div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#140c28"><title>EDC Fit Check</title>
  <style>
  :root {
    color-scheme: dark;
    --paper: #140c28;
    --panel: #22143a;
    --ink: #f6eaff;
    --muted: #d7c5e9;
    --line: #694e80;
    --accent: #e2fc55;
    --display: "Avenir Next", "Trebuchet MS", sans-serif;
    font-family: system-ui, sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; }
  body { margin: 0; background: var(--paper); color: var(--ink); line-height: 1.5; }
  ::selection { background: var(--accent); color: var(--paper); }
  button, input, textarea { font: inherit; }
  a { color: var(--accent); text-underline-offset: .2em; }
  a:hover { text-decoration: none; }
  .wrap { width: min(1080px, calc(100% - 48px)); margin-inline: auto; }
  .masthead { background: var(--paper); border-bottom: 1px solid var(--line); }
  .organizer-tabs { display: flex; gap: 16px; }
  .organizer-tabs a { padding: 8px 2px; border-bottom: 2px solid transparent; color: var(--ink); font-weight: 700; text-decoration: none; }
  .organizer-tabs a:hover { color: var(--accent); }
  .organizer-tabs a[aria-current] { color: var(--accent); border-bottom-color: var(--accent); }
  .manage-voting { padding-top: 16px; }
  .hero--workflow:has(+ .manage-voting) { margin-bottom: 0; }
  .top { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding-block: 13px; }
  .logo { font: 900 1.12rem var(--display); letter-spacing: -.035em; }
  .edition { color: var(--accent); font-weight: 800; font-size: .74rem; text-transform: uppercase; letter-spacing: .08em; text-align: right; }
  .hero {
    position: relative;
    color: white;
    overflow: hidden;
    background:
      radial-gradient(ellipse at 71% 110%, #ed3987 0%, #772269 28%, transparent 68%),
      linear-gradient(123deg, #140826, #2d0c4f 55%, #251151);
    width: min(1080px, calc(100% - 48px));
    margin: 24px auto 0;
    border: 1px solid var(--line);
    border-radius: 18px;
  }
  .hero-inner {
    position: relative;
    display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    align-items: center; gap: 26px; min-height: 375px; padding-inline: clamp(0px, 1vw, 18px);
  }
  .hero--workflow { margin-bottom: 12px; }
  .hero--workflow .hero-inner { grid-template-columns: minmax(0, 1fr) auto; min-height: 0; }
  .hero--workflow .hero-copy { padding: 12px 0; }
  .hero--workflow h1 { font-size: clamp(1.55rem, 5vw, 2.8rem); line-height: 1; }
  .hero--workflow h1 em { display: inline; }
  .hero--workflow :is(.hero-kicker, p) { display: none; }
  .hero--workflow .lotus { width: 112px; margin-block: 8px; }
  .hero-copy { padding: 35px 0; }
  .hero h1 { margin: 0; font: 900 clamp(3rem, 7.4vw, 5.8rem)/.91 var(--display); letter-spacing: -.04em; text-transform: uppercase; }
  .hero h1 em { display: block; color: var(--accent); font-style: normal; }
  .hero-kicker { color: var(--accent); font-size: .75rem; font-weight: 850; letter-spacing: .14em; text-transform: uppercase; margin-bottom: 12px; }
  .hero-action { display: inline-block; padding: 10px 16px; margin-top: 18px; background: var(--accent); color: var(--paper); border-radius: 7px; text-decoration: none; font-weight: 850; }
  .hero-action:hover { background: #f0ff9a; }
  .hero-action:disabled { background: #514b5c; color: #e3dfea; cursor: not-allowed; }
  .hero-action[hidden] { display: none; }
  .hero p { margin: 20px 0 0; max-width: 39ch; color: #f7e6ff; font-size: 1.05rem; }
  .lotus { display: block; width: min(100%, 475px); aspect-ratio: 368 / 346; justify-self: end; margin-block: 12px; filter: drop-shadow(0 14px 22px #1907238a); }
  .lotus img { display: block; width: 100%; height: auto; }
  .fireworks {
    position: absolute;
    inset: 0 0 0 39%;
    width: 61%;
    height: 100%;
    pointer-events: none;
  }
  .firework {
    opacity: .55;
    transform-origin: 0 0;
    animation: burst 2.35s cubic-bezier(.19, 1, .22, 1) var(--delay) both;
  }
  .firework-trails {
    animation: flare 2.35s ease-out var(--delay) both;
    filter: drop-shadow(0 0 2px var(--glow));
  }
  @keyframes burst {
    0% { opacity: 0; transform: scale(.12); }
    18% { opacity: .98; }
    65% { opacity: .86; }
    100% { opacity: .55; transform: scale(1); }
  }
  @keyframes flare {
    0% { opacity: .25; }
    23% { opacity: 1; }
    100% { opacity: .78; }
  }
  .fireworks.is-resetting :is(.firework, .firework-trails) { animation: none; }
  @media (prefers-reduced-motion: reduce) {
    .firework, .firework-trails { animation: none; }
  }
  .steps[hidden] { display: none; }
  .steps { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 24px 0 28px; }
  .step { display: flex; align-items: center; gap: 13px; min-width: 0; padding: 12px 15px; border: 1px solid var(--line); border-radius: 12px; }
  .step.current { border-color: #9273ae; background: #2d1c45; }
  .step.current.voting { border-color: var(--accent); }
  .step.current.voting b { color: var(--accent); }
  .step.complete { border-color: #55515c; background: #25222b; color: #c8c5ce; }
  .step.complete small { color: #b9b5c1; }
  .step.complete .number { background: #393540; color: #c8c5ce; }
  .step b { display: block; font-size: .94rem; }
  .step small { display: block; color: var(--muted); }
  .number { display: grid; place-items: center; flex: none; width: 36px; height: 36px; border-radius: 8px; background: #3a2852; color: var(--ink); font-weight: 850; font-variant-numeric: tabular-nums; }
  .current .number { background: var(--accent); color: var(--paper); }
  .board { display: grid; gap: 12px; }
  .idea-page { max-width: 650px; margin: 24px auto; }
  .idea-page > a { display: inline-block; margin-bottom: 12px; }
  .idea-page h1 { margin: 0; font: 850 clamp(1.6rem, 4vw, 2.3rem)/1.15 var(--display); }
  .idea { scroll-margin-top: 16px; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: clamp(17px, 3vw, 28px); margin-bottom: 16px; }
  .panel h2 { margin: 0; font: 850 clamp(1.3rem, 2.6vw, 1.65rem)/1.15 var(--display); letter-spacing: -.03em; }
  .panel p { color: var(--muted); }
  .hint { margin: .35rem 0 1rem; }
  .small { font-size: .88rem; }
  .head { display: flex; align-items: start; justify-content: space-between; gap: 12px; }
  .status { background: #e7f7b2; color: #283a0e; border-radius: 999px; padding: .38rem .68rem; font-size: .72rem; font-weight: 850; letter-spacing: .06em; text-transform: uppercase; white-space: nowrap; }
  .status.off { background: #eee5f2; color: #523461; }
  .deadline { padding-bottom: 12px; border-bottom: 1px solid var(--line); font-size: .92rem; }
  .empty { text-align: center; padding: 26px 12px; border: 1px dashed #bfa4c6; background: var(--paper); border-radius: 12px; margin-top: 20px; }
  .empty svg { width: 30px; height: 30px; color: var(--accent); margin-bottom: 5px; }
  .empty strong { display: block; }
  .empty p { margin: .35rem 0 0; }
  .ideas { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; padding: 0; margin: 0; list-style: none; }
  .idea { display: flex; flex-direction: column; gap: 12px; min-width: 0; padding: 15px; border: 1px solid var(--line); border-radius: 13px; background: #1c102f; overflow-wrap: anywhere; }
  .idea h3 { margin: 0; font-size: 1.06rem; }
  .idea p { margin: 0; }
  .idea .notes { margin-top: .4rem; white-space: pre-wrap; }
  .idea a { display: inline-block; margin-top: .5rem; font-size: .9rem; }
  label { display: block; font-size: .89rem; font-weight: 750; margin: 12px 0 5px; }
  label span { color: var(--muted); font-weight: 400; font-size: .78rem; }
  input, textarea { width: 100%; min-width: 0; background: var(--paper); color: var(--ink); border: 1px solid var(--line); border-radius: 8px; padding: 10px 11px; caret-color: var(--accent); }
  textarea { resize: vertical; min-height: 70px; }
  input::placeholder, textarea::placeholder { color: #b39cc9; }
  button { display: inline-block; cursor: pointer; border: 0; border-radius: 8px; background: var(--accent); color: var(--paper); font-weight: 850; padding: 11px 17px; margin-top: 14px; }
  button:hover { background: #f0ff9a; }
  :is(button, a, input, textarea):focus-visible { outline: 3px solid #ecb8ff; outline-offset: 3px; }
  .notice { padding: 10px 12px; margin: 0 0 16px; border-radius: 8px; background: #e9f5ce; color: #29410d; }
  .error { background: #fbe0ec; color: #7e1948; }
  .gate { max-width: 500px; margin: 26px auto; }
  .footer { margin-top: 28px; padding: 18px 0 30px; border-top: 1px solid var(--line); color: var(--muted); font-size: .85rem; }

  #vote-link-status:empty { display: none; }
  .vote-panel { scroll-margin-top: 12px; }
  .vote-panel textarea { margin-top: 3px; }
  .rank-board { padding-bottom: 82px; }
  .rank-board .ideas { grid-template-columns: minmax(0, 1fr); }
  .rank-board .idea { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; cursor: pointer; }
  .rank-board .idea-photos { grid-column: 1; }
  .rank-board .idea:has(.rank-pick[aria-pressed="true"]) { border-color: var(--accent); background: #2d1c45; }
  .rank-pick { grid-column: 2; grid-row: 1 / span 2; min-width: 62px; min-height: 44px; margin: 0; padding: 8px; }
  .rank-pick[aria-pressed="false"] { border: 1px solid var(--line); background: var(--panel); color: var(--ink); }
  .rank-pick[aria-disabled="true"], .rank-bar button:disabled { opacity: .65; cursor: default; }
  .rank-bar { position: fixed; z-index: 5; inset: auto 0 0; background: var(--panel); border-top: 1px solid var(--line); padding: 8px 0 calc(8px + env(safe-area-inset-bottom)); }
  .rank-bar .wrap, .rank-review-actions { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 12px; }
  .rank-bar button, .rank-review-actions button { margin: 0; min-height: 44px; }
  .rank-review { margin: auto; width: min(460px, calc(100% - 32px)); max-height: 90vh; color: var(--ink); }
  .rank-review::backdrop { background: #090511da; }
  .rank-review ol { padding-left: 1.5em; overflow-wrap: anywhere; }
  .rank-review li + li { margin-top: .5rem; }
  .rank-review-actions .edit-picks { background: var(--paper); color: var(--ink); border: 1px solid var(--line); }
  .vote-roster { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 170px), 1fr)); gap: 10px; padding: 0; list-style: none; }
  .voter-card { display: block; height: 100%; padding: 12px 14px; border: 1px solid var(--line); border-radius: 9px; background: var(--paper); color: var(--ink); overflow-wrap: anywhere; }
  a.voter-card { text-decoration: none; }
  a.voter-card:hover, a.voter-card:focus-visible { border-color: var(--accent); }
  .voter-card small { display: block; color: var(--muted); }
  .vote-results { width: 100%; border-collapse: collapse; font-size: .9rem; }
  .vote-results :is(th,td) { padding: 7px 4px; border-bottom: 1px solid var(--line); text-align: left; }
  .admin-dashboard { display: grid; align-items: start; gap: 12px; }
  .admin-dashboard .panel { margin-bottom: 0; }
  .admin-dashboard .ideas { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
  .admin-dashboard .idea { padding: 10px; gap: 6px; }
  @media (min-width: 800px) {
    .admin-dashboard { grid-template-columns: minmax(0, 2fr) minmax(0, 3fr); }
    .admin-roster { grid-column: 1 / -1; }
  }
  @media (max-width: 480px) {
    .admin-dashboard .ideas { grid-template-columns: minmax(0, 1fr); }
  }
  .admin-dashboard dialog.panel { margin: auto; }
  .admin-rankings .hint { margin-bottom: .5rem; }
  .admin-rankings .vote-results th[scope="row"] { overflow-wrap: anywhere; }
  .admin-rankings .vote-results :is(th,td):last-child { text-align: right; font-variant-numeric: tabular-nums; }
  .admin-rankings .vote-results td:last-child { color: var(--accent); font-weight: 700; }
  .idea-copy { min-width: 0; }
  .idea-photos { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .idea-photos:empty { display: none; }
  .idea-photo { position: relative; flex: none; }
  .board-status { display: grid; justify-items: end; gap: 2px; }
  .photo-edit { margin: 0; padding: 4px 0; background: transparent; color: var(--accent); font-size: .83rem; text-decoration: underline; }
  .photo-edit:hover { background: transparent; color: var(--ink); }
  .remove-photo { position: absolute; top: -4px; right: -4px; }
  .remove-photo button { display: grid; place-items: center; width: 25px; height: 25px; border: 1px solid var(--line); border-radius: 50%; padding: 0; margin: 0; background: var(--paper); color: var(--accent); font-size: 1rem; line-height: 1; }
  .remove-photo button:hover { background: #3a2852; }
  .idea-photos a { position: relative; display: block; margin: 0; width: 47px; aspect-ratio: 1; }
  .idea-photos a > img { display: block; width: 100%; height: 100%; object-fit: cover; border: 2px solid #9a77b4; border-radius: 50%; background: var(--panel); }
  .idea-photos a:is(:hover, :focus-visible) { z-index: 1; }
  .idea-photos a:is(:hover, :focus-visible) > img { border-color: var(--accent); }
  .photo-hover { display: none; position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%); width: min(248px, 44vw); height: min(280px, 52vw); border: 1px solid var(--accent); border-radius: 12px; background: var(--paper); box-shadow: 0 13px 35px #08040dcc; overflow: hidden; pointer-events: none; }
  .photo-hover img { display: block; width: 100%; height: 100%; object-fit: contain; }
  .idea:nth-child(3n + 1) .photo-hover { left: 0; transform: none; }
  .idea:nth-child(3n) .photo-hover { left: auto; right: 0; transform: none; }
  .idea-photos a:focus-visible .photo-hover { display: block; }
  @media (hover: hover) { .idea-photos a:hover .photo-hover { display: block; } }
  .full-photo { margin: auto; width: min(670px, calc(100% - 32px)); max-height: 90vh; }
  .full-photo::backdrop { background: #090511da; }
  .full-photo .head { align-items: center; margin-bottom: 12px; }
  .full-photo button { margin: 0; }
  .full-photo img { display: block; width: 100%; max-height: 70vh; object-fit: contain; }
  .photo-drop { position: relative; display: grid; justify-items: center; gap: 3px; margin: 0; padding: 15px 12px; border: 1px dashed #a97b9e; border-radius: 8px; background: var(--paper); color: var(--accent); text-align: center; cursor: pointer; }
  .photo-drop:hover, .photo-drop.is-dragging { background: #2d1c45; border-color: var(--accent); }
  .photo-drop:focus-within { outline: 3px solid #ecb8ff; outline-offset: 3px; }
  .photo-drop input { position: absolute; width: 1px; height: 1px; clip-path: inset(50%); padding: 0; }
  .photo-drop small { color: var(--muted); font-weight: 400; }
  .photo-status { overflow-wrap: anywhere; margin: 6px 0 0; font-size: .82rem; }
  .photo-status:empty, .selected-photos:empty { display: none; }
  .selected-photos { padding: 0; margin: 10px 0 0; list-style: none; }
  .selected-photos li { display: grid; grid-template-columns: 38px minmax(0, 1fr) auto; align-items: center; gap: 9px; padding: 7px 0; border-bottom: 1px solid var(--line); }
  .selected-photos img { width: 38px; height: 38px; object-fit: cover; border-radius: 6px; background: #f6eaf4; }
  .selected-photos strong, .selected-photos small { display: block; overflow-wrap: anywhere; }
  .selected-photos small, .idea .photo-added { color: #cce891; }
  .photo-remove, .photo-cancel { background: transparent; color: var(--accent); margin: 0; padding: 7px; text-decoration: underline; font-size: .85rem; }
  .photo-remove:hover, .photo-cancel:hover { background: #3a2852; }
  .photo-plus { margin: 0; padding: 0; flex: none; width: 34px; height: 34px; border: 1px dashed #aa769b; border-radius: 50%; background: #fff8fd; color: var(--accent); font-size: 1.25rem; line-height: 1; }
  .photo-plus:hover { background: #3a2852; }
  .photo-dialog { margin: auto; width: min(440px, calc(100% - 32px)); max-height: calc(100% - 32px); color: var(--ink); }
  .photo-dialog::backdrop { background: #21132e86; }
  .photo-dialog-actions { display: flex; gap: 8px; align-items: baseline; }
  form button:disabled { opacity: .55; cursor: default; }
  @media (max-width: 720px) {
    #ideas { padding: 12px; }
    #ideas .head { align-items: center; gap: 8px; }
    #outfit-ideas-heading { font-size: 1.15rem; }
    #ideas .head .hint { margin: 2px 0 0; font-size: .82rem; }
    #ideas .deadline { margin: 6px 0 8px; padding-bottom: 6px; font-size: .8rem; line-height: 1.3; }
    .guest-admin-link { display: none; }
    .wrap { width: calc(100% - 32px); }
    .hero-inner { gap: 0; grid-template-columns: 1fr; min-height: 0; text-align: center; }
    .hero-copy { padding: 24px 0 0; }
    .fireworks { inset: auto 0 0; width: 100%; height: 62%; }
    .hero h1 { font-size: clamp(2.6rem, 10vw, 4.1rem); }
    .hero h1 em { display: inline; }
    .hero p { margin: 11px auto 0; font-size: .96rem; }
    .lotus { width: min(67%, 300px); margin: 0 0 10px; justify-self: center; }
    .hero { width: calc(100% - 32px); }
    .ideas { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .idea { gap: 8px; padding: 11px; }
    .idea-photos a { width: 38px; }
    .idea:nth-child(odd) .photo-hover { left: 0; right: auto; transform: none; }
    .idea:nth-child(even) .photo-hover { left: auto; right: 0; transform: none; }
    .steps { margin: 16px 0 19px; gap: 8px; }
    .step { gap: 8px; padding: 9px; }
    .step .number { width: 28px; height: 32px; }
    :is(.board-page .hero, .hero--workflow) { margin-top: 12px; }
    :is(.board-page .hero, .hero--workflow) .hero-inner { grid-template-columns: minmax(0, 1fr) auto; gap: 8px; text-align: left; }
    :is(.board-page .hero, .hero--workflow) .hero-copy { padding: 12px 0; }
    :is(.board-page .hero, .hero--workflow) h1 { font-size: clamp(1.55rem, 6vw, 2.5rem); line-height: 1; }
    :is(.board-page .hero, .hero--workflow) :is(.hero-kicker, p, #add-idea-closed) { display: none; }
    :is(.board-page .hero, .hero--workflow) .lotus { width: clamp(68px, 23vw, 124px); margin: 4px 0; }
    .organizer-tabs { flex-wrap: wrap; align-items: center; gap: 4px 14px; }
    .organizer-tabs a { display: flex; align-items: center; min-height: 44px; }
    .organizer-tabs button { margin: 0; }
    .vote-panel { scroll-margin-top: 8px; }
    .vote-panel :is(input, select), .gate input { min-height: 46px; font-size: 16px; }
    .vote-panel form > button, .gate form > button { width: 100%; min-height: 46px; }
    .idea-photos a, .photo-plus { width: 44px; }
    .photo-plus { height: 44px; }
  }
  @media (max-width: 480px) {
    .top { gap: 8px; }
    .edition { font-size: .62rem; }
    .vote-fields, .ideas { grid-template-columns: minmax(0, 1fr); }
    .vote-fields { gap: 0; }
    .steps { margin-block: 10px; }
    .step { gap: 6px; }
    .step small { font-size: .72rem; }
    .step b { font-size: .82rem; }
    .footer { padding-bottom: 18px; }
  }
  @media (hover: none) {
    .photo-hover { display: none; }
  }
  @media (min-width: 900px) and (min-height: 580px) {
    .board-page .masthead { display: flex; align-items: center; gap: 20px; padding-inline: max(24px, calc((100% - 1080px) / 2)); }
    .board-page .masthead .top { padding-block: 8px; }
    .board-page .masthead .organizer-tabs { width: auto; flex: none; margin: 0; align-items: center; }
    .board-page .masthead .organizer-tabs button { margin: 0; padding: 6px 10px; }
    :is(.board-page .hero, .hero--workflow) { margin-top: 8px; border-radius: 12px; }
    :is(.board-page .hero, .hero--workflow) .hero-inner { grid-template-columns: minmax(0, 1fr) auto; min-height: 0; gap: 16px; }
    :is(.board-page .hero, .hero--workflow) .hero-copy { padding-block: 10px; }
    :is(.board-page .hero, .hero--workflow) h1 { font-size: clamp(1.8rem, 3.5vw, 2.8rem); line-height: 1; }
    :is(.board-page .hero, .hero--workflow) h1 em { display: inline; }
     :is(.board-page .hero, .hero--workflow) :is(.hero-kicker, p, #add-idea-closed) { display: none; }
    :is(.board-page .hero, .hero--workflow) .hero-action { margin-top: 8px; padding: 7px 12px; }
    :is(.board-page .hero, .hero--workflow) .lotus { width: clamp(164px, 24vh, 224px); margin-block: 9px; }
    .board-page .steps { margin: 9px 0; }
    .board-page .step { padding: 6px 12px; }
    .board-page .vote-panel { margin-bottom: 9px; padding: 12px 16px; }
    .board-page .vote-panel .hint { margin-bottom: .5rem; }
    .board-page #ideas { margin: 0; padding: 12px 16px; }
    .board-page #ideas .hint { margin-bottom: 0; }
    .board-page .deadline { margin: 6px 0 10px; padding-bottom: 6px; }
    .board-page .ideas { gap: 8px; }
    .board-page .board:not(.rank-board) .ideas { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .board-page .idea { padding: 10px; gap: 6px; }
    .board-page .idea h3 { font-size: 1rem; }
    .board-page .footer { margin-top: 8px; padding: 6px 0; }
  }
  </style></head><body${boardView ? ' class="board-page"' : ''}>
  <header class="masthead"><div class="top wrap"><div class="logo">EDC FIT CHECK</div><span class="edition">Phuket · Crew outfit board</span></div>
    ${role === 'organizer' ? `<nav class="organizer-tabs wrap" aria-label="Organizer navigation">
      <a href="/" ${manageView ? '' : 'aria-current="page"'}>Outfit ideas</a>
      <a href="/admin" ${manageView ? 'aria-current="page"' : ''}>Admin</a>
      <form method="post" action="/admin"><button type="submit" name="action" value="signout">Sign out</button></form>
    </nav>` : `<nav class="organizer-tabs guest-admin-link wrap" aria-label="Admin navigation"><a href="/admin" ${adminView ? 'aria-current="page"' : ''}>Admin</a></nav>`}
  </header>
  ${ideaView || adminView ? '' : `<section class="hero${voteView || manageView ? ' hero--workflow' : ''}">
    ${fireworks}
    <script>
      (() => {
        const display = document.querySelector('.fireworks');
        const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
        setInterval(() => {
          if (document.hidden || reducedMotion.matches) return;
          const bounds = display.getBoundingClientRect();
          if (bounds.bottom <= 0 || bounds.top >= window.innerHeight) return;
          display.classList.add('is-resetting');
          requestAnimationFrame(() => requestAnimationFrame(() => display.classList.remove('is-resetting')));
        }, 5 * 60 * 1000);
      })();
    </script>
    <div class="wrap hero-inner">
    <div class="hero-copy"><div class="hero-kicker">Under the electric sky</div><h1>EDC <em>Fit Check</em></h1><p>Drop a look you’d love to wear. Once the idea list is set, the crew can pick its favorites.</p>
    ${role && !voteView && !manageView ? `
      ${closed || role === 'visitor' ? '' : `<a class="hero-action" id="add-idea-link" href="/idea">Add an idea <span aria-hidden="true">↗</span></a>`}
      <button class="hero-action" id="add-idea-closed" type="button" disabled title="Idea submissions are closed" ${closed ? '' : 'hidden'}>Add an idea</button>
      ${!closed && deadline && role !== 'visitor' ? `<script>
        (() => {
          const deadline = ${Number(deadline)};
          const link = document.getElementById('add-idea-link');
          const closed = document.getElementById('add-idea-closed');
          let timer;
          const checkDeadline = () => {
            clearTimeout(timer);
            const remaining = deadline - Date.now();
            if (remaining > 0) {
              timer = setTimeout(checkDeadline, Math.min(remaining, 2147483647));
            } else {
              link.hidden = true;
              closed.hidden = false;
            }
          };
          window.addEventListener('pageshow', checkDeadline);
          document.addEventListener('visibilitychange', checkDeadline);
          checkDeadline();
        })();
      </script>` : ''}
    ` : ''}</div>
    <picture class="lotus">
      <source media="(prefers-reduced-motion: no-preference)" srcset="/lotus-bloom.webp" width="368" height="346">
      <img src="/outfit-planning.webp" width="960" height="817" alt="EDC Thailand lotus logo with Outfit on the left and Planning on the right" fetchpriority="high">
    </picture>
    <script>
      (() => {
        const source = document.querySelector('.lotus source');
        const logo = source.parentElement;
        const original = source.srcset;
        const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
        let animation;
        let activeUrl;
        const isVisible = () => {
          const bounds = logo.getBoundingClientRect();
          return !document.hidden && !reducedMotion.matches && bounds.bottom > 0 && bounds.top < innerHeight;
        };
        setInterval(async () => {
          if (!isVisible()) return;
          try {
            animation ??= fetch(original).then(response => {
              if (!response.ok) throw new Error('Lotus animation unavailable');
              return response.blob();
            });
            const blob = await animation;
            if (!isVisible()) return;
            const nextUrl = URL.createObjectURL(blob);
            source.srcset = nextUrl;
            if (activeUrl) URL.revokeObjectURL(activeUrl);
            activeUrl = nextUrl;
          } catch {
            animation = undefined;
          }
        }, 30000);
      })();
    </script>
  </div></section>`}
  <main class="wrap${manageView ? ' manage-voting' : ''}">
  <script>
  (() => {
    const match = /^#voter=([A-Za-z0-9_-]{32})$/.exec(location.hash);
    if (!match) return;
    fetch('/vote', {method:'POST', body:new URLSearchParams({action:'join',key:match[1]}), redirect:'manual'})
      .then(response => {
        if (response.type === 'opaqueredirect') location.replace('/vote?joined=1#voting');
        else throw Error();
      }).catch(() => {
        const status = document.getElementById('vote-link-status');
        if (status) status.textContent = 'This voting link could not be opened. Check with the organizer.';
      });
  })();
  </script>
  <p id="vote-link-status" class="hint" role="status"></p>
  ${adminView ? `<section class="panel gate"><h1>Admin sign-in</h1>
    ${error ? '<p class="notice error" role="alert">'+safe(error)+'</p>' : ''}
    <form method="post" action="/admin">
      <label for="admin-password">Password</label>
      <input id="admin-password" name="password" type="password" autocomplete="current-password" maxlength="128" required>
      <button type="submit">Sign in</button>
    </form>
  </section>` : !role ? `<section class="panel gate"><h2>${unavailable ? 'The board is taking a breather' : (personalLink ? 'Open your voting link' : 'You’re on the guest list?')}</h2>
  <p id="gate-message" role="status">${unavailable ? 'The board couldn’t load. Please try again in a moment.' : (personalLink ? 'Use the personal voting link sent by your organizer.' : 'Open the invite link from your organizer to see and add outfit ideas.')}</p></section>
  <script>
  (()=>{const hash=location.hash.slice(1);if(!/^invite=[A-Za-z0-9_-]{32}$/.test(hash))return;
  const key=hash.split('=')[1];const msg=document.getElementById('gate-message');msg.textContent='Opening your outfit board…';
  fetch('/join',{method:'POST',body:new URLSearchParams({key}),redirect:'manual'}).then(r=>{
  if(r.type!=='opaqueredirect')throw Error();location.replace('/');
  }).catch(()=>{msg.textContent='This link couldn’t open the board. Check the invite link and try again.';});})();
  </script>` : `
  ${ideaView ? `<div class="idea-page">
    <a href="/#ideas">← Back to outfit ideas</a>
    ${error ? '<p class="notice error" role="alert">'+safe(error)+'</p>' : ''}
    ${closed ? '<section class="panel"><h1>Idea submissions are closed</h1><p>You can still browse the outfits on the board.</p></section>' : `
    <section class="panel"><h1>Add an outfit idea</h1><p class="hint">Give your look a name and share what makes it fun.</p>
    <form id="idea-form" data-photo-form action="/idea" method="post">
      <label for="title">Outfit name</label><input id="title" name="title" required maxlength="80" value="${safe(fields.title)}" placeholder="e.g. Chrome cowgirls">
      <label for="author">Your name</label><input id="author" name="author" required maxlength="40" value="${safe(fields.author)}" autocomplete="given-name" placeholder="What the crew calls you">
      <label for="notes">Outfit details <span>optional</span></label><textarea id="notes" name="notes" maxlength="500" rows="2" placeholder="Colors, accessories, or the whole look">${safe(fields.notes)}</textarea>
      <label for="link">Inspiration link <span>optional</span></label><input id="link" name="link" type="url" maxlength="1000" value="${safe(fields.link)}" placeholder="https://…">
      <label for="inspo-photos">Inspiration photos <span>optional</span></label>
      ${photoPicker('inspo-photos', 'Choose photos together or one at a time')}
      <button type="submit">Done</button>
    </form></section><script>${photoFormScript}</script>`}
  </div>` : `
  <nav class="steps" aria-label="Poll stages" ${manageView || nameGate ? 'hidden' : ''}>
    <div class="step ${closed ? 'complete' : 'current'}" ${closed ? '' : 'aria-current="step"'}>
      <span class="number">01</span><div><b>Collect ideas</b><small>${closed ? 'Submissions closed' : 'Open for submissions'}</small></div>
    </div>
    <div class="step voting ${votingActive ? 'current' : ''}" ${votingActive ? 'aria-current="step"' : ''}>
      <span class="number">02</span><div><b>Rank your picks</b><small>${phase === 'open' ? 'Voting is open' : phase === 'closed' ? 'Results are in' : 'Voting is locked'}</small></div>
    </div>
  </nav>
  ${notice ? '<p class="notice" role="status">'+safe(notice)+'</p>' : ''}
  ${error ? '<p class="notice error" role="alert">'+safe(error)+'</p>' : ''}
  ${renderVoting({role,phase,voting,voter,ideas,closed,manageView,voteView,nameGate,alreadyVoted,outfitBoard})}
  ${manageView || nameGate ? '' : outfitBoard}`}`}
  ${role === 'organizer' ? `<script>
    for (const button of document.querySelectorAll('.photo-edit')) {
      button.addEventListener('click', () => {
        const editing = button.getAttribute('aria-expanded') !== 'true';
        const list = document.getElementById(button.getAttribute('aria-controls'));
        for (const control of list.querySelectorAll('.remove-photo')) control.hidden = !editing;
        button.setAttribute('aria-expanded', String(editing));
        button.textContent = editing ? 'Done editing' : 'Edit photos';
      });
    }
  </script>` : ''}
  </main><footer class="footer wrap">EDC Fit Check · Friends’ outfit board</footer></body></html>`;
}

function photoPicker(id, help) {
  return `<label class="photo-drop" for="${id}">
    <input id="${id}" type="file" accept="image/*" multiple aria-label="Choose inspiration photos" aria-describedby="${id}-help">
    <strong>Drop photos here or tap to choose</strong>
    <small class="photo-help" id="${id}-help">${help}</small>
  </label>
  <ul class="selected-photos" aria-label="Selected photos"></ul>
  <p class="photo-status" role="status"></p>`;
}

const photoFormScript = `
(() => {
  async function encodePhoto(file) {
    const bitmap = await createImageBitmap(file);
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      for (const edge of [1280, 960, 640]) {
        const scale = Math.min(1, edge / Math.max(bitmap.width, bitmap.height));
        canvas.width = Math.max(1, Math.round(bitmap.width * scale));
        canvas.height = Math.max(1, Math.round(bitmap.height * scale));
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
        const photo = canvas.toDataURL('${PHOTO_TYPE}', .8).split(',')[1];
        if (photo && photo.length <= ${PHOTO_BASE64_LIMIT}) return photo;
      }
      throw new Error('Photo is too large');
    } finally {
      bitmap.close();
    }
  }

  function setupPicker(form) {
    const picker = form.querySelector('input[type="file"]');
    const drop = form.querySelector('.photo-drop');
    const status = form.querySelector('.photo-status');
    const rows = form.querySelector('.selected-photos');
    const submit = form.querySelector('[type="submit"]');
    const cancel = form.querySelector('.photo-cancel');
    const required = form.hasAttribute('data-required');
    const entries = [];
    let ideaId = '';
    let preparation = Promise.resolve();
    let submitting = false;

    function refresh() {
      const ready = entries.length > 0 && entries.every(entry => entry.photo);
      submit.disabled = submitting || (required && !ready) || (entries.length > 0 && !ready);
    }

    function addFiles(files) {
      let message = '';
      for (const file of files) {
        if (file.size > 25 * 1024 * 1024) {
          message = file.name+' is larger than 25 MB.';
          continue;
        }
        if (entries.some(entry => entry.file.name === file.name && entry.file.size === file.size && entry.file.lastModified === file.lastModified)) continue;

        const row = document.createElement('li');
        const preview = document.createElement('img');
        preview.alt = '';
        const caption = document.createElement('div');
        const name = document.createElement('strong');
        name.textContent = file.name;
        const state = document.createElement('small');
        state.textContent = 'Preparing…';
        caption.append(name, state);
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'photo-remove';
        remove.textContent = 'Remove';
        remove.setAttribute('aria-label', 'Remove '+file.name);
        const entry = {file, row, state, remove, photo:null, saved:false};
        entries.push(entry);
        row.append(preview, caption, remove);
        rows.append(row);
        remove.addEventListener('click', () => {
          entries.splice(entries.indexOf(entry), 1);
          if (entry.preview) URL.revokeObjectURL(entry.preview);
          row.remove();
          status.textContent = file.name+' removed.';
          picker.focus();
          refresh();
        });
        preparation = preparation.then(async () => {
          if (!entries.includes(entry)) return;
          const photo = await encodePhoto(file);
          if (!entries.includes(entry)) return;
          entry.photo = photo;
          const bytes = Uint8Array.from(atob(photo), character => character.charCodeAt(0));
          entry.preview = URL.createObjectURL(new Blob([bytes], {type:'${PHOTO_TYPE}'}));
          preview.src = entry.preview;
          state.textContent = 'Ready to upload';
        }).catch(() => {
          if (!entries.includes(entry)) return;
          state.textContent = 'Couldn’t open. Remove it and try another photo.';
        }).finally(refresh);
      }
      status.textContent = message || (entries.length ? entries.length+' selected.' : '');
      refresh();
    }

    picker.addEventListener('change', () => {
      addFiles(picker.files);
      picker.value = '';
    });
    for (const type of ['dragenter','dragover','dragleave','drop']) {
      drop.addEventListener(type, event => {
        event.preventDefault();
        drop.classList.toggle('is-dragging', type === 'dragenter' || type === 'dragover');
        if (type === 'drop' && !submitting) addFiles(event.dataTransfer.files);
      });
    }
    async function sendPhotos(url, body) {
      const response = await fetch(url, {
        method:'POST',
        headers:{Accept:'application/json'},
        body,
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || 'The upload couldn’t finish. Try again.');
      return result;
    }

    form.addEventListener('submit', async event => {
      if (!required && !entries.length && !ideaId) return;
      event.preventDefault();
      if (submitting || entries.some(entry => !entry.photo)) return;
      submitting = true;
      picker.disabled = true;
      if (cancel) cancel.disabled = true;
      for (const entry of entries) entry.remove.disabled = true;
      refresh();

      try {
        if (required) ideaId = form.elements.idea.value;
        while (entries.some(entry => !entry.saved)) {
          const batch = entries.filter(entry => !entry.saved).slice(0, ${PHOTO_BATCH_SIZE});
          const creating = !ideaId;
          const body = creating ? new URLSearchParams(new FormData(form)) : new URLSearchParams({idea:ideaId});
          for (const entry of batch) {
            body.append('photo', entry.photo);
            entry.state.textContent = 'Uploading…';
          }
          status.textContent = 'Saving photos…';
          const result = await sendPhotos(creating ? '/idea' : '/inspo', body);
          if (creating) {
            ideaId = result.id;
            if (!ideaId) throw new Error('The board couldn’t confirm the idea. Check the board before retrying.');
          }
          for (const entry of batch) {
            entry.saved = true;
            entry.state.textContent = 'Added to the board';
          }
        }
        location.assign('/?photoIdea='+ideaId+'&photoAdded='+entries.length+'#idea-'+ideaId);
      } catch (error) {
        for (const entry of entries) {
          if (!entry.saved) entry.state.textContent = 'Ready to retry';
        }
        status.textContent = (ideaId && !required ? 'Your idea is on the board. ' : '')+error.message;
      } finally {
        submitting = false;
        picker.disabled = false;
        if (cancel) cancel.disabled = false;
        for (const entry of entries) entry.remove.disabled = entry.saved;
        refresh();
      }
    });

    return {
      reset() {
        ideaId = '';
        for (const entry of entries) {
          if (entry.preview) URL.revokeObjectURL(entry.preview);
        }
        entries.length = 0;
        rows.replaceChildren();
        picker.value = '';
        status.textContent = '';
        refresh();
      }
    };
  }

  const ideaForm = document.getElementById('idea-form');
  if (ideaForm) setupPicker(ideaForm);
  const dialog = document.getElementById('photo-dialog');
  if (!dialog) return;
  const form = dialog.querySelector('form');
  const picker = setupPicker(form);
  for (const button of document.querySelectorAll('.photo-plus')) {
    button.addEventListener('click', () => {
      form.elements.idea.value = button.dataset.idea;
      document.getElementById('photo-dialog-idea').textContent = button.dataset.title;
      picker.reset();
      dialog.showModal();
    });
  }
  dialog.querySelector('.photo-cancel').addEventListener('click', () => dialog.close());
  dialog.addEventListener('cancel', event => {
    if (form.querySelector('.photo-cancel').disabled) event.preventDefault();
  });
})();
`;

function firework(id, x, y, radius, rays, color, glow, delay) {
  // Repeat the same irregular spread on each render.
  let seed = 91 + id * 37;
  function random() {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  }
  const trail = [];
  const sparks = [];
  const point = (angle, length, fall = 0) =>
    (Math.cos(angle) * length).toFixed(1)+' '+(Math.sin(angle) * length + fall).toFixed(1);

  for (let ray = 0; ray < rays; ray++) {
    const angle = (ray + random() * .8) * 2 * Math.PI / rays;
    const length = radius * (.48 + random() * .54);
    const bend = radius * (.03 + random() * .17);
    const start = length * (.08 + random() * .36);
    trail.push('<path d="M '+point(angle,start)+' Q '+point(angle,length*.74)+' '+point(angle,length,bend)+'" stroke-width="'+(.45+random()*1.45).toFixed(2)+'" opacity="'+(.48+random()*.51).toFixed(2)+'"/>');

    for (let spark = 0; spark < 3; spark++) {
      const spread = length * (.2 + random() * 1.12);
      const position = point(angle + (random() - .5) * .27, spread, bend * random());
      const [cx,cy] = position.split(' ');
      sparks.push('<circle cx="'+cx+'" cy="'+cy+'" r="'+(.35+random()*1.15).toFixed(2)+'" opacity="'+(.2+random()*.77).toFixed(2)+'"/>');
    }
  }

  const gradient = 'fw-'+id;
  return `
    <defs>
      <radialGradient id="${gradient}" gradientUnits="userSpaceOnUse" cx="0" cy="0" r="${radius}">
        <stop stop-color="#fff5fd"/>
        <stop offset=".35" stop-color="${color}"/>
        <stop offset=".82" stop-color="${glow}"/>
        <stop offset="1" stop-color="${glow}" stop-opacity=".48"/>
      </radialGradient>
    </defs>
    <g transform="translate(${x} ${y})" style="--delay:${delay}s;--glow:${glow}">
      <g class="firework">
        <g class="firework-trails" fill="none" stroke="url(#${gradient})" stroke-linecap="round">${trail.join('')}</g>
        <g fill="url(#${gradient})">${sparks.join('')}</g>
        <circle r="2.1" fill="${color}"/>
      </g>
    </g>`;
}

const fireworks = `<svg class="fireworks" viewBox="0 0 650 390" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
  ${firework(1, 130, 145, 113, 37, '#eed1ff', '#a85aff', .24)}
  ${firework(2, 427, 54, 126, 43, '#fff0a2', '#ff8c46', .63)}
  ${firework(3, 556, 218, 114, 40, '#e9f9ff', '#8a92ff', .96)}
  ${firework(4, 233, 306, 62, 24, '#ffb6ea', '#ed53ae', 1.18)}
</svg>`;

function renderAdminRankings(ideas, voting) {
  const phase = votingPhase(voting);
  const voters = voting?.voters ?? [];
  const ballots = voters.filter(voter => voter.ballot).length;
  const rows = rankOutfits(ideas, voters).map(({rank, title, points}) =>
    `<tr><td>${rank}</td><th scope="row">${safe(title)}</th><td>${points}</td></tr>`).join('');
  const summary = phase === 'waiting' ? 'Rankings will update once voting opens.'
    : phase === 'open' ? 'Refreshes automatically every 5 seconds.' : 'Voting is closed.';
  return `<h2 id="admin-rankings-heading">${phase === 'closed' ? 'Final rankings' : 'Current rankings'}</h2>
    <p class="hint">${ballots} of ${voters.length} on the roster voted. ${summary}</p>
    <p class="hint">1st choice: 4 points · 2nd choice: 3 points · 3rd choice: 2 points</p>
    ${rows ? `<table class="vote-results" aria-labelledby="admin-rankings-heading"><thead><tr><th scope="col">Rank</th><th scope="col">Outfit</th><th scope="col">Points</th></tr></thead><tbody>${rows}</tbody></table>` : '<p>No outfits have been added yet.</p>'}`;
}

function renderVoting({role, phase, voting, voter, ideas, closed, manageView, voteView, nameGate, alreadyVoted, outfitBoard}) {
  const voters = voting?.voters ?? [];
  const organizer = role === 'organizer' && manageView;
  if (phase === 'waiting' && !organizer && !voter && !voteView) return '';

  let ballot = '';
  if (voter?.ballot) {
    const picks = voter.ballot.map(id => ideas.find(idea => idea.id === id)?.title ?? 'Outfit').map(title => '<li>'+safe(title)+'</li>').join('');
    ballot = `<h2>Your ballot is in, ${safe(firstName(voter.name))}</h2><ol>${picks}</ol>`;
  } else if (phase === 'open' && voter) {
    ballot = `<h2>Cast your vote, ${safe(firstName(voter.name))}</h2>
      <p class="hint">Tap three outfits in order of preference. Tap a pick again to remove it.</p>`;
  } else if (alreadyVoted) {
    ballot = '<h2>Ballot already submitted</h2><p class="hint">You can still browse the outfit ideas below.</p><p class="hint">If you’d like to change your ballot, contact the host.</p>';
  } else if (voteView && !organizer && (phase === 'open' || (phase === 'closed' && nameGate))) {
    ballot = `<h2>Enter your first name</h2>
      <form action="/vote" method="post">
        <input type="hidden" name="action" value="register">
        <label for="vote-name">First name</label>
        <input id="vote-name" name="name" autocomplete="given-name" maxlength="80" aria-describedby="guest-list-help" required>
        <p id="guest-list-help" class="hint">You can access this website if your first name is on the guest list. If you can’t get in, ask the host to add your name.</p>
        <button type="submit">Enter</button>
      </form>`;
  } else if (phase === 'open' && !organizer) {
    ballot = '<h2>Voting is open</h2><a class="btn" href="/vote#voting">Go to voting</a>';
  } else if (phase === 'waiting' && (voter || voteView)) {
    ballot = '<h2>Voting hasn’t opened yet</h2><p class="hint">Come back to this link when voting opens.</p>';
  }

  const results = phase === 'closed' && !organizer ? topOutfits(ideas,voters) : [];
  const resultsPanel = phase === 'closed' && !organizer ? `<div>
    <h2>Top outfits</h2><p class="hint">4 points for first, 3 for second, and 2 for third.</p>
    ${results.length ? `<table class="vote-results"><thead><tr><th scope="col">Rank</th><th scope="col">Outfit</th><th scope="col">1st / 2nd / 3rd</th><th scope="col">Points</th></tr></thead>
    <tbody>${results.map(result => `<tr><td>${result.rank}</td><th scope="row">${safe(result.title)}</th><td>${result.counts.join(' / ')}</td><td>${result.points}</td></tr>`).join('')}</tbody></table>` : '<p>No ballots were cast.</p>'}
  </div>` : '';

  const roster = organizer ? `<section class="panel vote-panel admin-roster" aria-labelledby="manage-voting-heading">
    <h2 id="manage-voting-heading">Manage voting</h2>
    ${phase !== 'closed' ? `<form action="/vote" method="post">
      <input type="hidden" name="action" value="roster"><label for="voter-names">Add voters, one first name per line</label>
      <textarea id="voter-names" name="names" rows="3" maxlength="20000" required></textarea>
      <button type="submit">Add to roster</button>
    </form>` : ''}
    ${voters.length ? `<ul class="vote-roster">${voters.map(entry => {
      const label = `<strong>${safe(firstName(entry.name))}</strong><small>${entry.ballot ? 'Voted' : 'Still to vote'}</small>`;
      const card = phase === 'closed' && !entry.ballot
        ? `<div class="voter-card">${label}</div>`
        : `<a class="voter-card" href="/vote#voter=${safe(entry.key)}" target="_blank" rel="noopener">${label}</a>`;
      return `<li>${card}</li>`;
    }).join('')}</ul>` : ''}
    ${phase === 'waiting' ? `<form action="/vote" method="post">
      <input type="hidden" name="action" value="open">
      <button type="submit" ${closed && ideas.length >= 3 ? '' : 'disabled'}>Open voting</button>
      <p class="small">Voting can open once idea submissions close and there are at least three outfits.</p>
    </form>` : ''}
    ${phase === 'open' ? `<form action="/vote" method="post" onsubmit="return confirm('Close voting and show the results?')">
      <input type="hidden" name="action" value="close"><button type="submit">Close voting and show results</button>
    </form>` : ''}
  </section>` : '';

  const adminRankings = organizer ? `<section class="panel admin-rankings" aria-labelledby="admin-rankings-heading">
    <div id="admin-rankings">${renderAdminRankings(ideas, voting)}</div><p id="rankings-status" class="hint" role="status" hidden></p>
  </section>${phase === 'closed' ? '' : `<script>
    (() => {
      const rankings = document.getElementById('admin-rankings');
      const status = document.getElementById('rankings-status');
      const refresh = async () => {
        if (!document.hidden) {
          try {
            const response = await fetch('/admin?view=rankings', {cache:'no-store'});
            if (response.status === 403) {
              location.replace('/admin');
              return;
            }
            if (!response.ok) throw new Error('Rankings unavailable');
            const updated = await response.text();
            if (rankings.innerHTML !== updated) rankings.innerHTML = updated;
            status.hidden = true;
          } catch {
            status.textContent = 'Couldn’t refresh the rankings. Trying again shortly.';
            status.hidden = false;
          }
        }
        setTimeout(refresh, 5000);
      };
      setTimeout(refresh, 5000);
    })();
  </script>`}` : '';

  if (organizer) {
    return `<div class="admin-dashboard" id="voting">${adminRankings}${outfitBoard}${roster}</div>`;
  }

  return `<section class="panel vote-panel" id="voting">${ballot}${nameGate ? '' : resultsPanel}
  </section>`;
}

const rankControls = `
  <div class="rank-bar"><div class="wrap">
    <strong id="pick-count" role="status">0 of 3 picked</strong>
    <button id="review-picks" type="button" disabled>Review picks</button>
  </div></div>
  <dialog class="panel rank-review" id="rank-review" aria-labelledby="rank-review-title">
    <h2 id="rank-review-title">Review your picks</h2>
    <ol id="review-order"></ol>
    <p class="hint">Your ballot is final once submitted. Contact the host if you need a change.</p>
    <form id="ranked-ballot" action="/vote" method="post">
      <input type="hidden" name="action" value="ballot">
      <input type="hidden" name="first">
      <input type="hidden" name="second">
      <input type="hidden" name="third">
      <div class="rank-review-actions">
        <button class="edit-picks" type="button" autofocus>Edit picks</button>
        <button type="submit">Submit ballot</button>
      </div>
    </form>
  </dialog>
  <script>
    (() => {
      const list = document.getElementById('idea-list');
      if (!list) return;
      const count = document.getElementById('pick-count');
      const review = document.getElementById('review-picks');
      const dialog = document.getElementById('rank-review');
      const order = document.getElementById('review-order');
      const form = document.getElementById('ranked-ballot');
      const buttons = Array.from(list.querySelectorAll('.rank-pick'));
      const picks = [];
      const ranks = ['1st', '2nd', '3rd'];
      const titleFor = button => button.closest('.idea').querySelector('h3').textContent;

      list.addEventListener('click', event => {
        if (event.target.closest('a, button:not(.rank-pick), input') || window.getSelection()?.toString()) return;
        const button = event.target.closest('.idea')?.querySelector('.rank-pick');
        if (!button) return;
        const rank = picks.indexOf(button);
        if (rank >= 0) picks.splice(rank, 1);
        else if (picks.length < 3) picks.push(button);
        else return;
        for (const option of buttons) {
          const position = picks.indexOf(option);
          const selected = position >= 0;
          option.textContent = selected ? ranks[position] : 'Pick';
          option.setAttribute('aria-pressed', String(selected));
          option.setAttribute('aria-disabled', String(!selected && picks.length === 3));
          option.setAttribute('aria-label', selected ? ranks[position] + ' choice: ' + titleFor(option) : 'Pick ' + titleFor(option));
        }
        count.textContent = picks.length + ' of 3 picked';
        review.disabled = picks.length !== 3;
      });

      review.addEventListener('click', () => {
        order.replaceChildren(...picks.map((button, index) => {
          form.elements[['first', 'second', 'third'][index]].value = button.dataset.pick;
          const item = document.createElement('li');
          item.textContent = titleFor(button);
          return item;
        }));
        dialog.showModal();
      });
      dialog.querySelector('.edit-picks').addEventListener('click', () => dialog.close());
      form.addEventListener('submit', () => { form.querySelector('[type="submit"]').disabled = true; });
    })();
  </script>`;
