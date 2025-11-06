import { useEffect, useRef, useState, useCallback } from 'react';
import type {
  Player,
  Alien,
  Bullet,
  Shield,
  GameState,
  GameConfig,
} from './types';

const config: GameConfig = {
  canvasWidth: 800,
  canvasHeight: 600,
  playerSpeed: 5,
  playerSize: { width: 40, height: 30 },
  alienRows: 5,
  alienCols: 11,
  alienSize: { width: 30, height: 24 },
  alienSpacing: { horizontal: 15, vertical: 15 },
  alienStartY: 60,
  alienMoveSpeed: 1,
  alienDropDistance: 20,
  bulletSpeed: 7,
  bulletWidth: 4,
  bulletHeight: 15,
  shieldCount: 4,
  shieldWidth: 60,
  shieldHeight: 40,
  shieldY: 450,
  shieldGridSize: 5,
  initialLives: 3,
  alienShootProbability: 0.0003,
};

export default function Game() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [gameState, setGameState] = useState<GameState>('menu');
  const [score, setScore] = useState(0);
  const [lives, setLives] = useState(config.initialLives);
  const [highScore, setHighScore] = useState(0);

  const gameStateRef = useRef<{
    player: Player;
    aliens: Alien[];
    playerBullets: Bullet[];
    alienBullets: Bullet[];
    shields: Shield[];
    keys: { [key: string]: boolean };
    alienDirection: number;
    alienMoveSpeed: number;
    animationId: number | null;
    lastAlienShoot: number;
  }>({
    player: initializePlayer(),
    aliens: [],
    playerBullets: [],
    alienBullets: [],
    shields: [],
    keys: {},
    alienDirection: 1,
    alienMoveSpeed: config.alienMoveSpeed,
    animationId: null,
    lastAlienShoot: 0,
  });

  function initializePlayer(): Player {
    return {
      x: config.canvasWidth / 2 - config.playerSize.width / 2,
      y: config.canvasHeight - config.playerSize.height - 20,
      width: config.playerSize.width,
      height: config.playerSize.height,
      speed: config.playerSpeed,
      active: true,
    };
  }

  function initializeAliens(): Alien[] {
    const aliens: Alien[] = [];
    const totalWidth =
      config.alienCols * config.alienSize.width +
      (config.alienCols - 1) * config.alienSpacing.horizontal;
    const startX = (config.canvasWidth - totalWidth) / 2;

    const pointsByRow = [50, 40, 30, 20, 10];

    for (let row = 0; row < config.alienRows; row++) {
      for (let col = 0; col < config.alienCols; col++) {
        aliens.push({
          x:
            startX +
            col * (config.alienSize.width + config.alienSpacing.horizontal),
          y:
            config.alienStartY +
            row * (config.alienSize.height + config.alienSpacing.vertical),
          width: config.alienSize.width,
          height: config.alienSize.height,
          active: true,
          points: pointsByRow[row],
          row,
          col,
        });
      }
    }
    return aliens;
  }

  function initializeShields(): Shield[] {
    const shields: Shield[] = [];
    const spacing =
      (config.canvasWidth - config.shieldCount * config.shieldWidth) /
      (config.shieldCount + 1);

    for (let i = 0; i < config.shieldCount; i++) {
      const gridSize = config.shieldGridSize;
      const damage: boolean[][] = Array(gridSize)
        .fill(null)
        .map(() => Array(gridSize).fill(false));

      shields.push({
        x: spacing + i * (config.shieldWidth + spacing),
        y: config.shieldY,
        width: config.shieldWidth,
        height: config.shieldHeight,
        active: true,
        health: 100,
        maxHealth: 100,
        damage,
      });
    }
    return shields;
  }

  const resetGame = useCallback(() => {
    gameStateRef.current.player = initializePlayer();
    gameStateRef.current.aliens = initializeAliens();
    gameStateRef.current.playerBullets = [];
    gameStateRef.current.alienBullets = [];
    gameStateRef.current.shields = initializeShields();
    gameStateRef.current.alienDirection = 1;
    gameStateRef.current.alienMoveSpeed = config.alienMoveSpeed;
    gameStateRef.current.lastAlienShoot = 0;
    setScore(0);
    setLives(config.initialLives);
  }, []);

  const startGame = useCallback(() => {
    resetGame();
    setGameState('playing');
  }, [resetGame]);

  const drawPlayer = useCallback((ctx: CanvasRenderingContext2D, player: Player) => {
    if (!player.active) return;

    ctx.fillStyle = '#00ff00';
    ctx.strokeStyle = '#00cc00';
    ctx.lineWidth = 2;

    // Draw player ship
    ctx.beginPath();
    ctx.moveTo(player.x + player.width / 2, player.y);
    ctx.lineTo(player.x, player.y + player.height);
    ctx.lineTo(player.x + player.width, player.y + player.height);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();

    // Draw cockpit
    ctx.fillStyle = '#00ffff';
    ctx.fillRect(
      player.x + player.width / 2 - 3,
      player.y + 8,
      6,
      8
    );
  }, []);

  const drawAlien = useCallback((ctx: CanvasRenderingContext2D, alien: Alien) => {
    if (!alien.active) return;

    const colors = ['#ff0066', '#ff3366', '#ff6666', '#ff9966', '#ffcc66'];
    ctx.fillStyle = colors[alien.row];
    ctx.strokeStyle = '#ff0000';
    ctx.lineWidth = 2;

    // Draw alien body
    ctx.fillRect(
      alien.x + 6,
      alien.y + 6,
      alien.width - 12,
      alien.height - 12
    );

    // Draw eyes
    ctx.fillStyle = '#ffff00';
    ctx.fillRect(alien.x + 10, alien.y + 10, 4, 4);
    ctx.fillRect(alien.x + alien.width - 14, alien.y + 10, 4, 4);

    // Draw antennae
    ctx.strokeStyle = colors[alien.row];
    ctx.beginPath();
    ctx.moveTo(alien.x + 8, alien.y + 6);
    ctx.lineTo(alien.x + 5, alien.y);
    ctx.moveTo(alien.x + alien.width - 8, alien.y + 6);
    ctx.lineTo(alien.x + alien.width - 5, alien.y);
    ctx.stroke();
  }, []);

  const drawBullet = useCallback((ctx: CanvasRenderingContext2D, bullet: Bullet) => {
    if (!bullet.active) return;

    ctx.fillStyle = bullet.direction === 'up' ? '#ffff00' : '#ff0000';
    ctx.fillRect(bullet.x, bullet.y, bullet.width, bullet.height);
  }, []);

  const drawShield = useCallback((ctx: CanvasRenderingContext2D, shield: Shield) => {
    if (!shield.active) return;

    const cellWidth = shield.width / config.shieldGridSize;
    const cellHeight = shield.height / config.shieldGridSize;

    for (let row = 0; row < config.shieldGridSize; row++) {
      for (let col = 0; col < config.shieldGridSize; col++) {
        if (!shield.damage[row][col]) {
          const alpha = shield.health / shield.maxHealth;
          ctx.fillStyle = `rgba(0, 255, 255, ${alpha})`;
          ctx.fillRect(
            shield.x + col * cellWidth,
            shield.y + row * cellHeight,
            cellWidth - 1,
            cellHeight - 1
          );
        }
      }
    }
  }, []);

  const checkCollision = useCallback(
    (
      obj1: { x: number; y: number; width: number; height: number },
      obj2: { x: number; y: number; width: number; height: number }
    ): boolean => {
      return (
        obj1.x < obj2.x + obj2.width &&
        obj1.x + obj1.width > obj2.x &&
        obj1.y < obj2.y + obj2.height &&
        obj1.y + obj1.height > obj2.y
      );
    },
    []
  );

  const damageShield = useCallback((shield: Shield, bullet: Bullet) => {
    const cellWidth = shield.width / config.shieldGridSize;
    const cellHeight = shield.height / config.shieldGridSize;

    const col = Math.floor((bullet.x - shield.x) / cellWidth);
    const row = Math.floor((bullet.y - shield.y) / cellHeight);

    if (
      row >= 0 &&
      row < config.shieldGridSize &&
      col >= 0 &&
      col < config.shieldGridSize
    ) {
      if (!shield.damage[row][col]) {
        shield.damage[row][col] = true;
        shield.health -= 100 / (config.shieldGridSize * config.shieldGridSize);

        // Damage adjacent cells for more realistic destruction
        if (Math.random() > 0.5 && col + 1 < config.shieldGridSize) {
          shield.damage[row][col + 1] = true;
          shield.health -= 100 / (config.shieldGridSize * config.shieldGridSize);
        }

        if (shield.health <= 0) {
          shield.active = false;
        }
      }
    }
  }, []);

  const updateGame = useCallback(() => {
    const state = gameStateRef.current;

    // Move player
    if (state.keys['ArrowLeft'] && state.player.x > 0) {
      state.player.x -= state.player.speed;
    }
    if (
      state.keys['ArrowRight'] &&
      state.player.x < config.canvasWidth - state.player.width
    ) {
      state.player.x += state.player.speed;
    }

    // Move aliens
    let shouldDropAliens = false;
    let leftmostAlien = config.canvasWidth;
    let rightmostAlien = 0;

    state.aliens.forEach((alien) => {
      if (alien.active) {
        leftmostAlien = Math.min(leftmostAlien, alien.x);
        rightmostAlien = Math.max(rightmostAlien, alien.x + alien.width);
      }
    });

    if (
      (state.alienDirection === 1 && rightmostAlien >= config.canvasWidth) ||
      (state.alienDirection === -1 && leftmostAlien <= 0)
    ) {
      state.alienDirection *= -1;
      shouldDropAliens = true;
    }

    state.aliens.forEach((alien) => {
      if (alien.active) {
        if (shouldDropAliens) {
          alien.y += config.alienDropDistance;
        }
        alien.x += state.alienDirection * state.alienMoveSpeed;

        // Check if aliens reached bottom
        if (alien.y + alien.height >= config.shieldY) {
          setGameState('gameOver');
        }
      }
    });

    // Move bullets
    state.playerBullets.forEach((bullet) => {
      if (bullet.active) {
        bullet.y -= bullet.speed;
        if (bullet.y < 0) bullet.active = false;
      }
    });

    state.alienBullets.forEach((bullet) => {
      if (bullet.active) {
        bullet.y += bullet.speed;
        if (bullet.y > config.canvasHeight) bullet.active = false;
      }
    });

    // Collision detection: player bullets vs aliens
    state.playerBullets.forEach((bullet) => {
      if (!bullet.active) return;

      state.aliens.forEach((alien) => {
        if (alien.active && checkCollision(bullet, alien)) {
          bullet.active = false;
          alien.active = false;
          setScore((prev) => prev + alien.points);
        }
      });
    });

    // Collision detection: bullets vs shields
    state.playerBullets.forEach((bullet) => {
      if (!bullet.active) return;
      state.shields.forEach((shield) => {
        if (shield.active && checkCollision(bullet, shield)) {
          bullet.active = false;
          damageShield(shield, bullet);
        }
      });
    });

    state.alienBullets.forEach((bullet) => {
      if (!bullet.active) return;
      state.shields.forEach((shield) => {
        if (shield.active && checkCollision(bullet, shield)) {
          bullet.active = false;
          damageShield(shield, bullet);
        }
      });
    });

    // Collision detection: alien bullets vs player
    state.alienBullets.forEach((bullet) => {
      if (bullet.active && state.player.active && checkCollision(bullet, state.player)) {
        bullet.active = false;
        state.player.active = false;
        setLives((prev) => {
          const newLives = prev - 1;
          if (newLives > 0) {
            setTimeout(() => {
              state.player = initializePlayer();
            }, 1000);
          } else {
            setGameState('gameOver');
          }
          return newLives;
        });
      }
    });

    // Aliens shoot
    const activeAliens = state.aliens.filter((a) => a.active);
    if (activeAliens.length > 0 && Math.random() < config.alienShootProbability) {
      const shooter = activeAliens[Math.floor(Math.random() * activeAliens.length)];
      state.alienBullets.push({
        x: shooter.x + shooter.width / 2 - config.bulletWidth / 2,
        y: shooter.y + shooter.height,
        width: config.bulletWidth,
        height: config.bulletHeight,
        speed: config.bulletSpeed * 0.8,
        direction: 'down',
        active: true,
      });
    }

    // Clean up inactive bullets
    state.playerBullets = state.playerBullets.filter((b) => b.active);
    state.alienBullets = state.alienBullets.filter((b) => b.active);

    // Increase alien speed as they are destroyed
    const remainingAliens = activeAliens.length;
    const totalAliens = config.alienRows * config.alienCols;
    const speedMultiplier = 1 + (totalAliens - remainingAliens) / totalAliens;
    state.alienMoveSpeed = config.alienMoveSpeed * speedMultiplier;

    // Check victory
    if (remainingAliens === 0) {
      setGameState('victory');
    }
  }, [checkCollision, damageShield]);

  const render = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, config.canvasWidth, config.canvasHeight);

    // Draw stars background
    ctx.fillStyle = '#ffffff';
    for (let i = 0; i < 50; i++) {
      const x = (i * 137.5) % config.canvasWidth;
      const y = (i * 217.8) % config.canvasHeight;
      ctx.fillRect(x, y, 1, 1);
    }

    const state = gameStateRef.current;

    // Draw shields
    state.shields.forEach((shield) => drawShield(ctx, shield));

    // Draw player
    drawPlayer(ctx, state.player);

    // Draw aliens
    state.aliens.forEach((alien) => drawAlien(ctx, alien));

    // Draw bullets
    state.playerBullets.forEach((bullet) => drawBullet(ctx, bullet));
    state.alienBullets.forEach((bullet) => drawBullet(ctx, bullet));

    // Draw UI
    ctx.fillStyle = '#ffffff';
    ctx.font = '20px monospace';
    ctx.fillText(`Score: ${score}`, 20, 30);
    ctx.fillText(`Lives: ${lives}`, config.canvasWidth - 120, 30);
    ctx.fillText(`High: ${highScore}`, config.canvasWidth / 2 - 50, 30);
  }, [score, lives, highScore, drawPlayer, drawAlien, drawBullet, drawShield]);

  const gameLoop = useCallback(() => {
    if (gameState !== 'playing') return;

    updateGame();
    render();

    gameStateRef.current.animationId = requestAnimationFrame(gameLoop);
  }, [gameState, updateGame, render]);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    const state = gameStateRef.current;

    if (e.key === ' ' && gameState === 'playing') {
      e.preventDefault();

      // Limit player bullets on screen
      if (state.playerBullets.length < 3 && state.player.active) {
        state.playerBullets.push({
          x: state.player.x + state.player.width / 2 - config.bulletWidth / 2,
          y: state.player.y,
          width: config.bulletWidth,
          height: config.bulletHeight,
          speed: config.bulletSpeed,
          direction: 'up',
          active: true,
        });
      }
    }

    state.keys[e.key] = true;
  }, [gameState]);

  const handleKeyUp = useCallback((e: KeyboardEvent) => {
    gameStateRef.current.keys[e.key] = false;
  }, []);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('keyup', handleKeyUp);
    };
  }, [handleKeyDown, handleKeyUp]);

  useEffect(() => {
    if (gameState === 'playing') {
      gameStateRef.current.animationId = requestAnimationFrame(gameLoop);
    }

    return () => {
      if (gameStateRef.current.animationId) {
        cancelAnimationFrame(gameStateRef.current.animationId);
      }
    };
  }, [gameState, gameLoop]);

  useEffect(() => {
    if (gameState === 'gameOver' || gameState === 'victory') {
      setHighScore((prev) => Math.max(prev, score));
    }
  }, [gameState, score]);

  const renderMenu = () => (
    <div className="game-overlay">
      <div className="menu">
        <h1 className="title">GALACTIC CONFLICTS</h1>
        <div className="subtitle">A Space Invaders Experience</div>
        <button className="btn-primary" onClick={startGame}>
          START GAME
        </button>
        <div className="instructions">
          <h3>CONTROLS</h3>
          <p>← → Arrow Keys: Move</p>
          <p>SPACEBAR: Shoot</p>
        </div>
        {highScore > 0 && (
          <div className="high-score">HIGH SCORE: {highScore}</div>
        )}
      </div>
    </div>
  );

  const renderGameOver = () => (
    <div className="game-overlay">
      <div className="menu">
        <h1 className="title game-over">GAME OVER</h1>
        <div className="score-display">
          <div>FINAL SCORE: {score}</div>
          <div>HIGH SCORE: {highScore}</div>
        </div>
        <button className="btn-primary" onClick={startGame}>
          PLAY AGAIN
        </button>
        <button
          className="btn-secondary"
          onClick={() => setGameState('menu')}
        >
          MAIN MENU
        </button>
      </div>
    </div>
  );

  const renderVictory = () => (
    <div className="game-overlay">
      <div className="menu">
        <h1 className="title victory">VICTORY!</h1>
        <div className="subtitle">All invaders destroyed!</div>
        <div className="score-display">
          <div>FINAL SCORE: {score}</div>
          <div>HIGH SCORE: {highScore}</div>
        </div>
        <button className="btn-primary" onClick={startGame}>
          PLAY AGAIN
        </button>
        <button
          className="btn-secondary"
          onClick={() => setGameState('menu')}
        >
          MAIN MENU
        </button>
      </div>
    </div>
  );

  return (
    <div className="game-container">
      <canvas
        ref={canvasRef}
        width={config.canvasWidth}
        height={config.canvasHeight}
        className="game-canvas"
      />
      {gameState === 'menu' && renderMenu()}
      {gameState === 'gameOver' && renderGameOver()}
      {gameState === 'victory' && renderVictory()}
    </div>
  );
}
