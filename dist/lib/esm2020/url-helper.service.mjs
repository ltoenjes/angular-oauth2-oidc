import { Injectable } from '@angular/core';
import * as i0 from "@angular/core";
export class UrlHelperService {
    getHashFragmentParams(customHashFragment) {
        let hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        const questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    }
    parseQueryString(queryString) {
        const data = {};
        let pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (let i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            }
            else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }
            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);
            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }
            data[key] = value;
        }
        return data;
    }
}
UrlHelperService.ɵfac = i0.ɵɵngDeclareFactory({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: UrlHelperService, deps: [], target: i0.ɵɵFactoryTarget.Injectable });
UrlHelperService.ɵprov = i0.ɵɵngDeclareInjectable({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: UrlHelperService });
i0.ɵɵngDeclareClassMetadata({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: UrlHelperService, decorators: [{
            type: Injectable
        }] });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vcHJvamVjdHMvbGliL3NyYy91cmwtaGVscGVyLnNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQzs7QUFHM0MsTUFBTSxPQUFPLGdCQUFnQjtJQUNwQixxQkFBcUIsQ0FBQyxrQkFBMkI7UUFDdEQsSUFBSSxJQUFJLEdBQUcsa0JBQWtCLElBQUksTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUM7UUFFdEQsSUFBSSxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxDQUFDO1FBRWhDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDM0IsT0FBTyxFQUFFLENBQUM7U0FDWDtRQUVELE1BQU0sb0JBQW9CLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUUvQyxJQUFJLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxFQUFFO1lBQzdCLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxDQUFDO1NBQzlDO2FBQU07WUFDTCxJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUN2QjtRQUVELE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3JDLENBQUM7SUFFTSxnQkFBZ0IsQ0FBQyxXQUFtQjtRQUN6QyxNQUFNLElBQUksR0FBRyxFQUFFLENBQUM7UUFDaEIsSUFBSSxLQUFLLEVBQUUsSUFBSSxFQUFFLGNBQWMsRUFBRSxVQUFVLEVBQUUsWUFBWSxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUM7UUFFdEUsSUFBSSxXQUFXLEtBQUssSUFBSSxFQUFFO1lBQ3hCLE9BQU8sSUFBSSxDQUFDO1NBQ2I7UUFFRCxLQUFLLEdBQUcsV0FBVyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUUvQixLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsS0FBSyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRTtZQUNyQyxJQUFJLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLGNBQWMsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBRW5DLElBQUksY0FBYyxLQUFLLENBQUMsQ0FBQyxFQUFFO2dCQUN6QixVQUFVLEdBQUcsSUFBSSxDQUFDO2dCQUNsQixZQUFZLEdBQUcsSUFBSSxDQUFDO2FBQ3JCO2lCQUFNO2dCQUNMLFVBQVUsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxjQUFjLENBQUMsQ0FBQztnQkFDNUMsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsY0FBYyxHQUFHLENBQUMsQ0FBQyxDQUFDO2FBQ2hEO1lBRUQsR0FBRyxHQUFHLGtCQUFrQixDQUFDLFVBQVUsQ0FBQyxDQUFDO1lBQ3JDLEtBQUssR0FBRyxrQkFBa0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztZQUV6QyxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxLQUFLLEdBQUcsRUFBRTtnQkFDNUIsR0FBRyxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDckI7WUFFRCxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsS0FBSyxDQUFDO1NBQ25CO1FBRUQsT0FBTyxJQUFJLENBQUM7SUFDZCxDQUFDOzs2R0F0RFUsZ0JBQWdCO2lIQUFoQixnQkFBZ0I7MkZBQWhCLGdCQUFnQjtrQkFENUIsVUFBVSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFVybEhlbHBlclNlcnZpY2Uge1xuICBwdWJsaWMgZ2V0SGFzaEZyYWdtZW50UGFyYW1zKGN1c3RvbUhhc2hGcmFnbWVudD86IHN0cmluZyk6IG9iamVjdCB7XG4gICAgbGV0IGhhc2ggPSBjdXN0b21IYXNoRnJhZ21lbnQgfHwgd2luZG93LmxvY2F0aW9uLmhhc2g7XG5cbiAgICBoYXNoID0gZGVjb2RlVVJJQ29tcG9uZW50KGhhc2gpO1xuXG4gICAgaWYgKGhhc2guaW5kZXhPZignIycpICE9PSAwKSB7XG4gICAgICByZXR1cm4ge307XG4gICAgfVxuXG4gICAgY29uc3QgcXVlc3Rpb25NYXJrUG9zaXRpb24gPSBoYXNoLmluZGV4T2YoJz8nKTtcblxuICAgIGlmIChxdWVzdGlvbk1hcmtQb3NpdGlvbiA+IC0xKSB7XG4gICAgICBoYXNoID0gaGFzaC5zdWJzdHIocXVlc3Rpb25NYXJrUG9zaXRpb24gKyAxKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaGFzaCA9IGhhc2guc3Vic3RyKDEpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnBhcnNlUXVlcnlTdHJpbmcoaGFzaCk7XG4gIH1cblxuICBwdWJsaWMgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICBjb25zdCBkYXRhID0ge307XG4gICAgbGV0IHBhaXJzLCBwYWlyLCBzZXBhcmF0b3JJbmRleCwgZXNjYXBlZEtleSwgZXNjYXBlZFZhbHVlLCBrZXksIHZhbHVlO1xuXG4gICAgaWYgKHF1ZXJ5U3RyaW5nID09PSBudWxsKSB7XG4gICAgICByZXR1cm4gZGF0YTtcbiAgICB9XG5cbiAgICBwYWlycyA9IHF1ZXJ5U3RyaW5nLnNwbGl0KCcmJyk7XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHBhaXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBwYWlyID0gcGFpcnNbaV07XG4gICAgICBzZXBhcmF0b3JJbmRleCA9IHBhaXIuaW5kZXhPZignPScpO1xuXG4gICAgICBpZiAoc2VwYXJhdG9ySW5kZXggPT09IC0xKSB7XG4gICAgICAgIGVzY2FwZWRLZXkgPSBwYWlyO1xuICAgICAgICBlc2NhcGVkVmFsdWUgPSBudWxsO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZXNjYXBlZEtleSA9IHBhaXIuc3Vic3RyKDAsIHNlcGFyYXRvckluZGV4KTtcbiAgICAgICAgZXNjYXBlZFZhbHVlID0gcGFpci5zdWJzdHIoc2VwYXJhdG9ySW5kZXggKyAxKTtcbiAgICAgIH1cblxuICAgICAga2V5ID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZWRLZXkpO1xuICAgICAgdmFsdWUgPSBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlZFZhbHVlKTtcblxuICAgICAgaWYgKGtleS5zdWJzdHIoMCwgMSkgPT09ICcvJykge1xuICAgICAgICBrZXkgPSBrZXkuc3Vic3RyKDEpO1xuICAgICAgfVxuXG4gICAgICBkYXRhW2tleV0gPSB2YWx1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gZGF0YTtcbiAgfVxufVxuIl19