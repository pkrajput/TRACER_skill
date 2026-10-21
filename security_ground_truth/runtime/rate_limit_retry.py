"""Shared cooldown for explicit provider 429 rejections, without model rerolls.

Only a rejected HTTP request is retried. A completed response, malformed model
output, refusal, timeout or budget error is never retried by this wrapper.
After a cooldown only one real pending request probes provider availability.
"""
from email.utils import parsedate_to_datetime
import threading
import time
import urllib.error
import http.client


def retry_after_seconds(headers,now=None):
    value=(headers or {}).get('Retry-After')
    if value is None:return 0.0
    try:return max(0.0,float(value))
    except (TypeError,ValueError):
        try:return max(0.0,parsedate_to_datetime(value).timestamp()-(time.time() if now is None else now))
        except (TypeError,ValueError,OverflowError):return 0.0


class RateLimitRetry:
    def __init__(self,generate,*,stopped=lambda:False,base_delay=60,max_delay=300,
                 max_attempts=6,max_wait=1800,retry_transient=False):
        self.generate=generate;self.stopped=stopped
        self.base_delay=base_delay;self.max_delay=max_delay
        self.max_attempts=max_attempts;self.max_wait=max_wait
        self.condition=threading.Condition();self.until=0.0;self.recovering=False
        self.probe_active=False;self.next_delay=base_delay
        self.retry_transient=retry_transient

    def acquire(self,deadline):
        with self.condition:
            while True:
                if self.stopped():raise RuntimeError('Campaign stopped before provider request')
                now=time.monotonic()
                if now>=deadline:raise TimeoutError('Provider rate-limit cooldown exceeded bounded wait')
                delay=self.until-now
                if delay>0 or (self.recovering and self.probe_active):
                    self.condition.wait(min(1,deadline-now,max(.001,delay) if delay>0 else 1));continue
                probe=self.recovering
                if probe:self.probe_active=True
                return probe

    def limited(self,probe,headers):
        with self.condition:
            now=time.monotonic();hint=retry_after_seconds(headers)
            if not self.recovering or probe or self.until<=now:
                delay=max(self.next_delay,hint)
                self.until=now+delay;self.next_delay=min(self.max_delay,max(self.base_delay,2*self.next_delay))
            else:self.until=max(self.until,now+hint)
            self.recovering=True
            if probe:self.probe_active=False
            self.condition.notify_all()

    def released(self,probe,success):
        if not probe:return
        with self.condition:
            self.probe_active=False
            if success:
                self.recovering=False;self.until=0;self.next_delay=self.base_delay
            self.condition.notify_all()

    def __call__(self,*args,**kwargs):
        deadline=time.monotonic()+self.max_wait
        for attempt in range(self.max_attempts):
            probe=self.acquire(deadline)
            try:value=self.generate(*args,**kwargs)
            except urllib.error.HTTPError as error:
                if error.code!=429 and not (self.retry_transient and error.code in {502,503,504}):
                    self.released(probe,False);raise
                self.limited(probe,error.headers)
                if attempt+1==self.max_attempts:raise
            except (urllib.error.URLError,ConnectionError,http.client.IncompleteRead,TimeoutError) as error:
                # Opt-in execution revision only. Unknown billing reservations
                # remain charged; a model response is never silently rerolled.
                if not self.retry_transient:
                    self.released(probe,False);raise
                self.limited(probe,{})
                if attempt+1==self.max_attempts:raise
            except Exception:
                self.released(probe,False);raise
            else:
                self.released(probe,True);return value
