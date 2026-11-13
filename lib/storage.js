import { randomBytes, randomUUID } from 'node:crypto';
import { BlobNotFoundError, BlobPreconditionFailedError, del, get, head, put } from '@vercel/blob';
import { firstName, votingPhase } from './voting.js';

const voterNameKey = name => name.normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
const boardPath = 'board.json';
const privateAccess = {access: 'private'};
const photoPath = (id, slot) => 'photos/'+id+'/'+slot+'.jpg';

async function readBoard() {
  const blob = await get(boardPath, {...privateAccess, useCache:false});
  return blob ? await new Response(blob.stream).json() : {deadline:null, ideas:[]};
}

async function boardVersion() {
  try {
    return (await head(boardPath)).etag;
  } catch (error) {
    if (error instanceof BlobNotFoundError) return null;
    throw error;
  }
}

async function updateBoard(change) {
  for (let attempt = 0; attempt < 6; attempt++) {
    // Read the storage API's version first so a concurrent write cannot be overwritten.
    const etag = await boardVersion();
    const board = await readBoard();
    const updated = change(board);
    if (!updated) return false;
    try {
      await put(boardPath, JSON.stringify(updated), {
        ...privateAccess,
        contentType:'application/json',
        ...(etag ? {ifMatch:etag} : {allowOverwrite:false}),
      });
      return true;
    } catch (error) {
      if (error instanceof BlobPreconditionFailedError) continue;
      // Another request may have created the first snapshot.
      if (!etag && await boardVersion()) continue;
      throw error;
    }
  }
  throw new Error('The board is busy. Please try again.');
}

function acceptsIdeas(board) {
  return board.ideas.length < 250 && (!board.deadline || board.deadline > Date.now());
}

async function uploadPhotos(paths, photos) {
  const uploads = await Promise.allSettled(photos.map((photo, slot) =>
    put(paths[slot], Buffer.from(photo, 'base64'), {...privateAccess, contentType:'image/jpeg'})
  ));
  const failure = uploads.find(upload => upload.status === 'rejected');
  if (failure) {
    await del(paths).catch(() => {});
    throw failure.reason;
  }
}

function keysForIdea(idea) {
  return Array.from({length:idea.photoCount ?? 0}, (_, index) => idea.photoKeys?.[index] ?? String(index));
}

export default {
  async read() {
    return readBoard();
  },

  async addIdea(fields, photos) {
    if (!acceptsIdeas(await this.read())) return false;
    const id = randomUUID();
    const paths = photos.map((_, slot) => photoPath(id, slot));
    await uploadPhotos(paths, photos);
    const idea = {...fields, id, photoCount:photos.length};
    const saved = await updateBoard(board =>
      acceptsIdeas(board) ? {...board, ideas:[idea, ...board.ideas]} : null
    );
    if (!saved && paths.length) await del(paths).catch(() => {});
    return saved ? id : false;
  },

  async addPhotos(id, photos) {
    const acceptsPhotos = (board, idea) =>
      idea && (!board.deadline || board.deadline > Date.now());

    const board = await this.read();
    if (!acceptsPhotos(board, board.ideas.find(idea => idea.id === id))) return false;
    const keys = photos.map(() => randomUUID());
    const paths = keys.map(key => photoPath(id, key));
    await uploadPhotos(paths, photos);
    const saved = await updateBoard(current => {
      const idea = current.ideas.find(entry => entry.id === id);
      if (!acceptsPhotos(current, idea)) return null;
      const photoKeys = [...keysForIdea(idea), ...keys];
      const updated = {...idea, photoKeys, photoCount:photoKeys.length};
      return {...current, ideas:current.ideas.map(entry => entry.id === id ? updated : entry)};
    });
    if (!saved) await del(paths).catch(() => {});
    return saved;
  },

  async removePhoto(id, key) {
    const removed = await updateBoard(board => {
      const idea = board.ideas.find(entry => entry.id === id);
      if (!idea) return null;
      const keys = keysForIdea(idea);
      if (!keys.includes(key)) return null;
      const photoKeys = keys.filter(entry => entry !== key);
      const updated = {...idea, photoKeys, photoCount:photoKeys.length};
      return {...board, ideas:board.ideas.map(entry => entry.id === id ? updated : entry)};
    });
    if (removed) {
      try {
        await del(photoPath(id, key));
      } catch (error) {
        console.error('Photo was removed from the board but its file could not be cleaned up.', error?.message);
      }
    }
    return removed;
  },

  addVoters(names) {
    return updateBoard(board => {
      if (votingPhase(board.voting) === 'closed') return null;
      const voters = [...(board.voting?.voters ?? [])];
      const known = new Set(voters.map(voter => voterNameKey(firstName(voter.name))));
      for (const name of names) {
        const givenName = firstName(name);
        const key = voterNameKey(givenName);
        if (known.has(key)) continue;
        known.add(key);
        voters.push({name:givenName, key:randomBytes(24).toString('base64url')});
      }
      if (voters.length > 250) return null;
      return {...board, voting:{...board.voting, voters}};
    });
  },

  findRosterVoter(board, name) {
    const key = voterNameKey(name);
    const voters = board.voting?.voters ?? [];
    if (key.includes(' ')) return voters.find(voter => voterNameKey(voter.name) === key);
    const matches = voters.filter(voter => voterNameKey(firstName(voter.name)) === key);
    return matches.length === 1 ? matches[0] : undefined;
  },

  startVoting() {
    return updateBoard(board => {
      if (!board.deadline || board.deadline > Date.now() || board.ideas.length < 3 ||
          votingPhase(board.voting) !== 'waiting') return null;
      return {...board, voting:{voters:[], ...board.voting, openedAt:Date.now()}};
    });
  },

  submitBallot(key, picks) {
    return updateBoard(board => {
      if (votingPhase(board.voting) !== 'open' || picks.length !== 3 || new Set(picks).size !== 3 ||
          !picks.every(pick => board.ideas.some(idea => idea.id === pick))) return null;
      const voter = board.voting.voters.find(entry => entry.key === key);
      if (!voter || voter.ballot) return null;
      const voters = board.voting.voters.map(entry => entry.key === key ? {...entry, ballot:picks} : entry);
      return {...board, voting:{...board.voting, voters}};
    });
  },

  closeVoting() {
    return updateBoard(board => {
      if (votingPhase(board.voting) !== 'open') return null;
      return {...board, voting:{...board.voting, closedAt:Date.now()}};
    });
  },

  setDeadline(deadline) {
    return updateBoard(board => {
      const now = Date.now();
      if (deadline <= now || (board.deadline && board.deadline <= now)) return null;
      return {...board, deadline};
    });
  },

  async getPhoto(id, slot) {
    const photo = await get(photoPath(id, slot), privateAccess);
    return photo?.stream ?? null;
  },
};
