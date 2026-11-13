const weights = [4, 3, 2];

export function firstName(name) {
  return name.normalize('NFKC').trim().split(/\s+/, 1)[0];
}

export function votingPhase(voting) {
  if (voting?.closedAt) return 'closed';
  if (voting?.openedAt) return 'open';
  return 'waiting';
}

export function topOutfits(ideas, voters) {
  return rankOutfits(ideas, voters).filter(tally => tally.points > 0 && tally.rank <= 3);
}

export function rankOutfits(ideas, voters) {
  const tallies = new Map(ideas.map(idea => [idea.id, {title:idea.title, counts:[0, 0, 0]}]));
  for (const voter of voters) {
    voter.ballot?.forEach((id, position) => {
      const tally = tallies.get(id);
      if (tally) tally.counts[position]++;
    });
  }
  const ranked = [...tallies.values()].map(tally => ({
    ...tally, points:tally.counts.reduce((total, count, position) => total + count * weights[position], 0),
  }));
  const compare = (a, b) => b.points-a.points || b.counts[0]-a.counts[0] || b.counts[1]-a.counts[1];
  ranked.sort((a,b) => compare(a,b) || a.title.localeCompare(b.title));
  let rank = 0;
  return ranked.map((tally, index) => {
    if (!index || compare(ranked[index-1], tally)) rank = index+1;
    return {...tally, rank};
  });
}
