import React, { useState, useEffect } from 'react';

export default function UserSettings() {
  const [profile, setProfile] = useState(null);

  useEffect(() => {
    // MALICIOUS REACT PATTERN: Frontend component calls hidden debug/bypass flag
    fetch('/api/v1/users/me?skip_auth=true', {
      method: 'GET'
    })
      .then(res => res.json())
      .then(data => setProfile(data));
  }, []);

  const triggerHugeRender = () => {
    // MALICIOUS DOM BOMB: Unbounded array rendering freezing browser renderer
    return new Array(25000).fill(0).map((_, i) => (
      <div key={i} className="item">Row {i}</div>
    ));
  };

  return (
    <div className="container">
      <h2>User Profile</h2>
      {profile && <p>{profile.name}</p>}
      {triggerHugeRender()}
    </div>
  );
}

