import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { QRCode } from 'react-qrcode-logo';

import { config } from './lib/config';
import { dropsToXrp, isLikelyXrplAddress, shortenAddress, stringToHex, toDrops } from './lib/format';
import { EthereumProvider, getProvider, getSnaps, invokeSnap, requestSnap } from './lib/metamask';

type SnapNetwork = {
  chainId: number;
  name: string;
  nodeUrl: string;
  explorerUrl?: string;
};

type WalletInfo = {
  address: string;
  publicKey: string;
  type: 'derived' | 'imported';
  isActive: boolean;
};

type XrplResponse<T> = {
  result: T;
};

const extractTxHash = (response: XrplResponse<{ engine_result?: string; tx_json?: { hash?: string } }>): string => {
  const engineResult = response?.result?.engine_result;
  if (engineResult && engineResult !== 'tesSUCCESS') {
    throw new Error(engineResult);
  }
  const hash = response?.result?.tx_json?.hash;
  if (!hash) {
    throw new Error('Transaction hash missing');
  }
  return hash;
};

export default function App() {
  const [provider, setProvider] = useState<EthereumProvider | null>(null);
  const [snapSelection, setSnapSelection] = useState({ id: config.snapId });
  const currentSnapSelection = useRef(snapSelection);
  const snapId = snapSelection.id;
  const [snapInstalled, setSnapInstalled] = useState(false);
  const [account, setAccount] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [wallets, setWallets] = useState<WalletInfo[]>([]);
  const [networks, setNetworks] = useState<SnapNetwork[]>([]);
  const [activeNetwork, setActiveNetwork] = useState<SnapNetwork | null>(null);
  const [balance, setBalance] = useState('0');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [sendDestination, setSendDestination] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sendMemo, setSendMemo] = useState('');
  const [sendDestinationTag, setSendDestinationTag] = useState('');
  const [sendTxHash, setSendTxHash] = useState('');

  const hasProvider = Boolean(provider);
  const hasSnapId = snapId.trim().length > 0;
  const isCurrentSnap = useCallback(() => currentSnapSelection.current === snapSelection, [snapSelection]);

  const resetStatus = () => {
    setStatus('');
    setError('');
  };

  const handleSnapIdChange = (id: string) => {
    if (id === snapId) {
      return;
    }
    // A new token invalidates old callbacks even when returning to the same ID.
    const nextSelection = { id };
    currentSnapSelection.current = nextSelection;
    setSnapSelection(nextSelection);
    setSnapInstalled(false);
    setAccount('');
    setPublicKey('');
    setWallets([]);
    setNetworks([]);
    setActiveNetwork(null);
    setBalance('0');
    resetStatus();
    setLoading(false);
    setSendDestination('');
    setSendAmount('');
    setSendMemo('');
    setSendDestinationTag('');
    setSendTxHash('');
  };

  const refreshSnapStatus = useCallback(async () => {
    if (!isCurrentSnap()) {
      return;
    }
    if (!provider || !hasSnapId) {
      setSnapInstalled(false);
      return;
    }
    try {
      const snaps = await getSnaps(provider);
      if (!isCurrentSnap()) {
        return;
      }
      setSnapInstalled(Boolean(snaps[snapId]));
    } catch (err) {
      if (isCurrentSnap()) {
        setSnapInstalled(false);
        setError((err as Error).message || 'Failed to read snaps');
      }
    }
  }, [provider, snapId, hasSnapId, isCurrentSnap]);

  const refreshBalance = useCallback(
    async (address: string) => {
      if (!isCurrentSnap()) {
        return;
      }
      if (!provider || !hasSnapId || !address) {
        setBalance('0');
        return;
      }
      try {
        const response = await invokeSnap<XrplResponse<{ account_data?: { Balance?: string } }>>(
          provider,
          snapId,
          'xrpl_request',
          {
            command: 'account_info',
            account: address,
          },
        );
        if (!isCurrentSnap()) {
          return;
        }
        const balanceDrops = response?.result?.account_data?.Balance || '0';
        setBalance(dropsToXrp(balanceDrops));
      } catch (err) {
        if (isCurrentSnap()) {
          setBalance('0');
          setError((err as Error).message || 'Failed to load balance');
        }
      }
    },
    [provider, snapId, hasSnapId, isCurrentSnap],
  );

  const loadAll = useCallback(async () => {
    if (!isCurrentSnap() || !provider || !hasSnapId) {
      return;
    }
    setLoading(true);
    resetStatus();
    try {
      const walletResponse = await invokeSnap<{ account: string; publicKey: string }>(
        provider,
        snapId,
        'xrpl_getAccount',
      );
      if (!isCurrentSnap()) {
        return;
      }
      setAccount(walletResponse.account);
      setPublicKey(walletResponse.publicKey);

      const walletsResponse = await invokeSnap<{ wallets: WalletInfo[] }>(provider, snapId, 'xrpl_listWallets');
      if (!isCurrentSnap()) {
        return;
      }
      setWallets(walletsResponse.wallets || []);

      const storedNetworks = await invokeSnap<SnapNetwork[]>(provider, snapId, 'xrpl_getStoredNetworks');
      if (!isCurrentSnap()) {
        return;
      }
      setNetworks(storedNetworks || []);

      const active = await invokeSnap<SnapNetwork>(provider, snapId, 'xrpl_getActiveNetwork');
      if (!isCurrentSnap()) {
        return;
      }
      setActiveNetwork(active || null);

      await refreshBalance(walletResponse.account);
    } catch (err) {
      if (isCurrentSnap()) {
        setError((err as Error).message || 'Failed to load wallet data');
      }
    } finally {
      if (isCurrentSnap()) {
        setLoading(false);
      }
    }
  }, [provider, snapId, hasSnapId, refreshBalance, isCurrentSnap]);

  const handleConnect = async () => {
    if (!isCurrentSnap()) {
      return;
    }
    if (!provider) {
      setError('MetaMask not detected');
      return;
    }
    if (!hasSnapId) {
      setError('Snap ID is required');
      return;
    }
    resetStatus();
    setLoading(true);
    try {
      await requestSnap(provider, snapId);
      if (!isCurrentSnap()) {
        return;
      }
      setStatus('Snap connected');
      await refreshSnapStatus();
      if (!isCurrentSnap()) {
        return;
      }
      await loadAll();
    } catch (err) {
      if (isCurrentSnap()) {
        setError((err as Error).message || 'Snap connection failed');
      }
    } finally {
      if (isCurrentSnap()) {
        setLoading(false);
      }
    }
  };

  const handleSwitchWallet = async (address: string) => {
    if (!isCurrentSnap() || !provider || !hasSnapId) {
      return;
    }
    resetStatus();
    setLoading(true);
    try {
      await invokeSnap(provider, snapId, 'xrpl_switchWallet', { address });
      if (!isCurrentSnap()) {
        return;
      }
      await loadAll();
      if (!isCurrentSnap()) {
        return;
      }
      setStatus('Wallet switched');
    } catch (err) {
      if (isCurrentSnap()) {
        setError((err as Error).message || 'Failed to switch wallet');
      }
    } finally {
      if (isCurrentSnap()) {
        setLoading(false);
      }
    }
  };

  const handleSwitchNetwork = async (chainId: number) => {
    if (!isCurrentSnap() || !provider || !hasSnapId) {
      return;
    }
    resetStatus();
    setLoading(true);
    try {
      await invokeSnap(provider, snapId, 'xrpl_changeNetwork', { chainId });
      if (!isCurrentSnap()) {
        return;
      }
      await loadAll();
      if (!isCurrentSnap()) {
        return;
      }
      setStatus('Network changed');
    } catch (err) {
      if (isCurrentSnap()) {
        setError((err as Error).message || 'Failed to change network');
      }
    } finally {
      if (isCurrentSnap()) {
        setLoading(false);
      }
    }
  };

  const handleSend = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isCurrentSnap()) {
      return;
    }
    if (!provider || !hasSnapId || !account) {
      setError('Wallet not connected');
      return;
    }

    const drops = toDrops(sendAmount);
    if (!drops) {
      setError('Enter a valid amount');
      return;
    }
    if (BigInt(drops) <= 0n) {
      setError('Amount must be greater than 0');
      return;
    }
    if (!sendDestination.trim()) {
      setError('Destination address is required');
      return;
    }
    if (!isLikelyXrplAddress(sendDestination)) {
      setError('Destination address looks invalid');
      return;
    }

    resetStatus();
    setSendTxHash('');
    setLoading(true);
    try {
      const tx: Record<string, unknown> = {
        TransactionType: 'Payment',
        Account: account,
        Destination: sendDestination.trim(),
        Amount: drops,
      };

      const tag = sendDestinationTag.trim();
      if (tag) {
        if (!/^\d+$/.test(tag)) {
          setError('Destination tag must be numeric');
          return;
        }
        const tagNumber = Number(tag);
        if (!Number.isSafeInteger(tagNumber) || tagNumber < 0) {
          setError('Destination tag must be a valid integer');
          return;
        }
        tx.DestinationTag = tagNumber;
      }

      const memo = sendMemo.trim();
      if (memo) {
        tx.Memos = [
          {
            Memo: {
              MemoData: stringToHex(memo),
            },
          },
        ];
      }

      const response = await invokeSnap<XrplResponse<{ engine_result?: string; tx_json?: { hash?: string } }>>(
        provider,
        snapId,
        'xrpl_signAndSubmit',
        tx,
      );
      if (!isCurrentSnap()) {
        return;
      }

      const hash = extractTxHash(response);
      setSendTxHash(hash);
      setStatus('Transaction submitted');
      await refreshBalance(account);
    } catch (err) {
      if (isCurrentSnap()) {
        setError((err as Error).message || 'Send failed');
      }
    } finally {
      if (isCurrentSnap()) {
        setLoading(false);
      }
    }
  };

  const activeWalletOptions = useMemo(() => {
    return wallets.length ? wallets : account ? [{ address: account, publicKey, type: 'derived', isActive: true }] : [];
  }, [wallets, account, publicKey]);

  useEffect(() => {
    const detected = getProvider();
    setProvider(detected);
  }, []);

  useEffect(() => {
    refreshSnapStatus().catch(() => undefined);
  }, [refreshSnapStatus]);

  useEffect(() => {
    if (snapInstalled) {
      loadAll().catch(() => undefined);
    }
  }, [snapInstalled, loadAll]);

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>PFTL Host Lite</h1>
          <p>Minimal host UI for MetaMask snap wallet actions.</p>
        </div>
        <div className="status">
          <span className={snapInstalled ? 'pill ok' : 'pill warn'}>{snapInstalled ? 'Snap connected' : 'Snap not connected'}</span>
        </div>
      </header>

      {!hasProvider && (
        <div className="card">
          <h2>MetaMask not detected</h2>
          <p>Install MetaMask with snaps support to continue.</p>
        </div>
      )}

      {hasProvider && (
        <div className="grid">
          <section className="card">
            <h2>Connect</h2>
            <label>
              Snap ID
              <input value={snapId} onChange={(event) => handleSnapIdChange(event.target.value)} placeholder="npm:@postfiat/pftl-snap" />
            </label>
            <div className="actions">
              <button onClick={handleConnect} disabled={!hasSnapId || loading}>
                Connect Snap
              </button>
              <button onClick={refreshSnapStatus} disabled={!hasSnapId || loading} className="ghost">
                Refresh Status
              </button>
            </div>
            <p className="small">Snap ID can be provided via VITE_SNAP_ID or window.__PFTL_HOST_CONFIG__.</p>
          </section>

          <section className="card">
            <h2>Account</h2>
            {account ? (
              <div className="stack">
                <div className="row">
                  <span className="label">Address</span>
                  <span className="mono">{shortenAddress(account)}</span>
                </div>
                <div className="row">
                  <span className="label">Public Key</span>
                  <span className="mono">{shortenAddress(publicKey)}</span>
                </div>
                <label>
                  Switch Wallet
                  <select
                    value={activeWalletOptions.find((wallet) => wallet.isActive)?.address || account}
                    onChange={(event) => handleSwitchWallet(event.target.value)}
                    disabled={!snapInstalled || loading}
                  >
                    {activeWalletOptions.map((wallet) => (
                      <option key={wallet.address} value={wallet.address}>
                        {wallet.type === 'imported' ? 'Imported' : 'Derived'} - {shortenAddress(wallet.address)}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            ) : (
              <p className="muted">Connect the snap to load account info.</p>
            )}
          </section>

          <section className="card">
            <h2>Network</h2>
            {activeNetwork ? (
              <div className="stack">
                <div className="row">
                  <span className="label">Active</span>
                  <span>{activeNetwork.name}</span>
                </div>
                <label>
                  Switch Network
                  <select
                    value={activeNetwork.chainId}
                    onChange={(event) => handleSwitchNetwork(Number(event.target.value))}
                    disabled={!snapInstalled || loading}
                  >
                    {networks.map((network) => (
                      <option key={network.chainId} value={network.chainId}>
                        {network.name}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            ) : (
              <p className="muted">No network data available.</p>
            )}
          </section>

          <section className="card">
            <h2>Balance</h2>
            <div className="row">
              <span className="label">PFTL</span>
              <span className="mono">{balance}</span>
            </div>
            <button onClick={() => refreshBalance(account)} disabled={!snapInstalled || loading || !account} className="ghost">
              Refresh Balance
            </button>
          </section>

          <section className="card wide">
            <h2>Send</h2>
            <form onSubmit={handleSend} className="stack">
              <label>
                Destination Address
                <input value={sendDestination} onChange={(event) => setSendDestination(event.target.value)} />
              </label>
              <label>
                Amount (PFTL)
                <input value={sendAmount} onChange={(event) => setSendAmount(event.target.value)} />
              </label>
              <label>
                Destination Tag (optional)
                <input value={sendDestinationTag} onChange={(event) => setSendDestinationTag(event.target.value)} />
              </label>
              <label>
                Memo (optional)
                <input value={sendMemo} onChange={(event) => setSendMemo(event.target.value)} maxLength={256} />
              </label>
              <button type="submit" disabled={!snapInstalled || loading}>
                Submit Payment
              </button>
              {sendTxHash && (
                <div className="small mono">
                  Tx: {sendTxHash}
                </div>
              )}
            </form>
          </section>

          <section className="card">
            <h2>Receive</h2>
            {account ? (
              <div className="stack">
                <QRCode value={account} size={160} quietZone={10} />
                <button
                  className="ghost"
                  onClick={() => navigator.clipboard.writeText(account)}
                  disabled={!account}
                >
                  Copy Address
                </button>
              </div>
            ) : (
              <p className="muted">Connect the snap to show the receive address.</p>
            )}
          </section>
        </div>
      )}

      {(status || error) && (
        <div className={`banner ${error ? 'error' : 'ok'}`}>
          {error || status}
        </div>
      )}

      {loading && <div className="overlay">Working...</div>}
    </div>
  );
}
