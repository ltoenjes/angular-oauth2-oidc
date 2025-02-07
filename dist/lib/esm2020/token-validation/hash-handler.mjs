import { Injectable } from '@angular/core';
import { factory } from './js-sha256';
import fsha256 from 'fast-sha256';
import * as i0 from "@angular/core";
const sha256 = factory();
/**
 * Abstraction for crypto algorithms
 */
export class HashHandler {
}
function decodeUTF8(s) {
    if (typeof s !== 'string')
        throw new TypeError('expected string');
    var i, d = s, b = new Uint8Array(d.length);
    for (i = 0; i < d.length; i++)
        b[i] = d.charCodeAt(i);
    return b;
}
function encodeUTF8(arr) {
    var i, s = [];
    for (i = 0; i < arr.length; i++)
        s.push(String.fromCharCode(arr[i]));
    return s.join('');
}
export class DefaultHashHandler {
    async calcHash(valueToHash, algorithm) {
        // const encoder = new TextEncoder();
        // const hashArray = await window.crypto.subtle.digest(algorithm, data);
        // const data = encoder.encode(valueToHash);
        // const fhash = fsha256(valueToHash);
        const candHash = encodeUTF8(fsha256(decodeUTF8(valueToHash)));
        // const hashArray = (sha256 as any).array(valueToHash);
        // // const hashString = this.toHashString(hashArray);
        // const hashString = this.toHashString2(hashArray);
        // console.debug('hash orig - cand', candHash, hashString);
        // alert(1);
        return candHash;
    }
    toHashString2(byteArray) {
        let result = '';
        for (let e of byteArray) {
            result += String.fromCharCode(e);
        }
        return result;
    }
    toHashString(buffer) {
        const byteArray = new Uint8Array(buffer);
        let result = '';
        for (let e of byteArray) {
            result += String.fromCharCode(e);
        }
        return result;
    }
}
DefaultHashHandler.ɵfac = i0.ɵɵngDeclareFactory({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: DefaultHashHandler, deps: [], target: i0.ɵɵFactoryTarget.Injectable });
DefaultHashHandler.ɵprov = i0.ɵɵngDeclareInjectable({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: DefaultHashHandler });
i0.ɵɵngDeclareClassMetadata({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: DefaultHashHandler, decorators: [{
            type: Injectable
        }] });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaC1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vcHJvamVjdHMvbGliL3NyYy90b2tlbi12YWxpZGF0aW9uL2hhc2gtaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRTNDLE9BQU8sRUFBRSxPQUFPLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFHdEMsT0FBTyxPQUFPLE1BQU0sYUFBYSxDQUFDOztBQUZsQyxNQUFNLE1BQU0sR0FBRyxPQUFPLEVBQUUsQ0FBQztBQUl6Qjs7R0FFRztBQUNILE1BQU0sT0FBZ0IsV0FBVztDQUVoQztBQUVELFNBQVMsVUFBVSxDQUFDLENBQUM7SUFDbkIsSUFBSSxPQUFPLENBQUMsS0FBSyxRQUFRO1FBQUUsTUFBTSxJQUFJLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO0lBQ2xFLElBQUksQ0FBQyxFQUNILENBQUMsR0FBRyxDQUFDLEVBQ0wsQ0FBQyxHQUFHLElBQUksVUFBVSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUMvQixLQUFLLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFO1FBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDdEQsT0FBTyxDQUFDLENBQUM7QUFDWCxDQUFDO0FBRUQsU0FBUyxVQUFVLENBQUMsR0FBRztJQUNyQixJQUFJLENBQUMsRUFDSCxDQUFDLEdBQUcsRUFBRSxDQUFDO0lBQ1QsS0FBSyxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRTtRQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ3JFLE9BQU8sQ0FBQyxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUNwQixDQUFDO0FBR0QsTUFBTSxPQUFPLGtCQUFrQjtJQUM3QixLQUFLLENBQUMsUUFBUSxDQUFDLFdBQW1CLEVBQUUsU0FBaUI7UUFDbkQscUNBQXFDO1FBQ3JDLHdFQUF3RTtRQUN4RSw0Q0FBNEM7UUFFNUMsc0NBQXNDO1FBRXRDLE1BQU0sUUFBUSxHQUFHLFVBQVUsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUU5RCx3REFBd0Q7UUFDeEQsc0RBQXNEO1FBQ3RELG9EQUFvRDtRQUVwRCwyREFBMkQ7UUFDM0QsWUFBWTtRQUVaLE9BQU8sUUFBUSxDQUFDO0lBQ2xCLENBQUM7SUFFRCxhQUFhLENBQUMsU0FBbUI7UUFDL0IsSUFBSSxNQUFNLEdBQUcsRUFBRSxDQUFDO1FBQ2hCLEtBQUssSUFBSSxDQUFDLElBQUksU0FBUyxFQUFFO1lBQ3ZCLE1BQU0sSUFBSSxNQUFNLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ2xDO1FBQ0QsT0FBTyxNQUFNLENBQUM7SUFDaEIsQ0FBQztJQUVELFlBQVksQ0FBQyxNQUFtQjtRQUM5QixNQUFNLFNBQVMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUN6QyxJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUM7UUFDaEIsS0FBSyxJQUFJLENBQUMsSUFBSSxTQUFTLEVBQUU7WUFDdkIsTUFBTSxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDbEM7UUFDRCxPQUFPLE1BQU0sQ0FBQztJQUNoQixDQUFDOzsrR0FuQ1Usa0JBQWtCO21IQUFsQixrQkFBa0I7MkZBQWxCLGtCQUFrQjtrQkFEOUIsVUFBVSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcblxuaW1wb3J0IHsgZmFjdG9yeSB9IGZyb20gJy4vanMtc2hhMjU2JztcbmNvbnN0IHNoYTI1NiA9IGZhY3RvcnkoKTtcblxuaW1wb3J0IGZzaGEyNTYgZnJvbSAnZmFzdC1zaGEyNTYnO1xuXG4vKipcbiAqIEFic3RyYWN0aW9uIGZvciBjcnlwdG8gYWxnb3JpdGhtc1xuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgSGFzaEhhbmRsZXIge1xuICBhYnN0cmFjdCBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPjtcbn1cblxuZnVuY3Rpb24gZGVjb2RlVVRGOChzKSB7XG4gIGlmICh0eXBlb2YgcyAhPT0gJ3N0cmluZycpIHRocm93IG5ldyBUeXBlRXJyb3IoJ2V4cGVjdGVkIHN0cmluZycpO1xuICB2YXIgaSxcbiAgICBkID0gcyxcbiAgICBiID0gbmV3IFVpbnQ4QXJyYXkoZC5sZW5ndGgpO1xuICBmb3IgKGkgPSAwOyBpIDwgZC5sZW5ndGg7IGkrKykgYltpXSA9IGQuY2hhckNvZGVBdChpKTtcbiAgcmV0dXJuIGI7XG59XG5cbmZ1bmN0aW9uIGVuY29kZVVURjgoYXJyKSB7XG4gIHZhciBpLFxuICAgIHMgPSBbXTtcbiAgZm9yIChpID0gMDsgaSA8IGFyci5sZW5ndGg7IGkrKykgcy5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoYXJyW2ldKSk7XG4gIHJldHVybiBzLmpvaW4oJycpO1xufVxuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRGVmYXVsdEhhc2hIYW5kbGVyIGltcGxlbWVudHMgSGFzaEhhbmRsZXIge1xuICBhc3luYyBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgLy8gY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuICAgIC8vIGNvbnN0IGhhc2hBcnJheSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEpO1xuICAgIC8vIGNvbnN0IGRhdGEgPSBlbmNvZGVyLmVuY29kZSh2YWx1ZVRvSGFzaCk7XG5cbiAgICAvLyBjb25zdCBmaGFzaCA9IGZzaGEyNTYodmFsdWVUb0hhc2gpO1xuXG4gICAgY29uc3QgY2FuZEhhc2ggPSBlbmNvZGVVVEY4KGZzaGEyNTYoZGVjb2RlVVRGOCh2YWx1ZVRvSGFzaCkpKTtcblxuICAgIC8vIGNvbnN0IGhhc2hBcnJheSA9IChzaGEyNTYgYXMgYW55KS5hcnJheSh2YWx1ZVRvSGFzaCk7XG4gICAgLy8gLy8gY29uc3QgaGFzaFN0cmluZyA9IHRoaXMudG9IYXNoU3RyaW5nKGhhc2hBcnJheSk7XG4gICAgLy8gY29uc3QgaGFzaFN0cmluZyA9IHRoaXMudG9IYXNoU3RyaW5nMihoYXNoQXJyYXkpO1xuXG4gICAgLy8gY29uc29sZS5kZWJ1ZygnaGFzaCBvcmlnIC0gY2FuZCcsIGNhbmRIYXNoLCBoYXNoU3RyaW5nKTtcbiAgICAvLyBhbGVydCgxKTtcblxuICAgIHJldHVybiBjYW5kSGFzaDtcbiAgfVxuXG4gIHRvSGFzaFN0cmluZzIoYnl0ZUFycmF5OiBudW1iZXJbXSkge1xuICAgIGxldCByZXN1bHQgPSAnJztcbiAgICBmb3IgKGxldCBlIG9mIGJ5dGVBcnJheSkge1xuICAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoZSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICB0b0hhc2hTdHJpbmcoYnVmZmVyOiBBcnJheUJ1ZmZlcikge1xuICAgIGNvbnN0IGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGJ1ZmZlcik7XG4gICAgbGV0IHJlc3VsdCA9ICcnO1xuICAgIGZvciAobGV0IGUgb2YgYnl0ZUFycmF5KSB7XG4gICAgICByZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIGhleFN0cmluZyhidWZmZXIpIHtcbiAgLy8gICAgIGNvbnN0IGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGJ1ZmZlcik7XG4gIC8vICAgICBjb25zdCBoZXhDb2RlcyA9IFsuLi5ieXRlQXJyYXldLm1hcCh2YWx1ZSA9PiB7XG4gIC8vICAgICAgIGNvbnN0IGhleENvZGUgPSB2YWx1ZS50b1N0cmluZygxNik7XG4gIC8vICAgICAgIGNvbnN0IHBhZGRlZEhleENvZGUgPSBoZXhDb2RlLnBhZFN0YXJ0KDIsICcwJyk7XG4gIC8vICAgICAgIHJldHVybiBwYWRkZWRIZXhDb2RlO1xuICAvLyAgICAgfSk7XG5cbiAgLy8gICAgIHJldHVybiBoZXhDb2Rlcy5qb2luKCcnKTtcbiAgLy8gICB9XG5cbiAgLy8gdG9IYXNoU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XG4gIC8vICAgbGV0IHJlc3VsdCA9ICcnO1xuICAvLyAgIGZvciAobGV0IGkgPSAwOyBpIDwgaGV4U3RyaW5nLmxlbmd0aDsgaSArPSAyKSB7XG4gIC8vICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XG4gIC8vICAgICBsZXQgbnVtID0gcGFyc2VJbnQoaGV4RGlnaXQsIDE2KTtcbiAgLy8gICAgIHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKG51bSk7XG4gIC8vICAgfVxuICAvLyAgIHJldHVybiByZXN1bHQ7XG4gIC8vIH1cbn1cbiJdfQ==