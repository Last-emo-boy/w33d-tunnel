export namespace main {
	
	export class Config {
	    sub_url: string;
	    socks_addr: string;
	    global_proxy: boolean;
	    auto_start: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sub_url = source["sub_url"];
	        this.socks_addr = source["socks_addr"];
	        this.global_proxy = source["global_proxy"];
	        this.auto_start = source["auto_start"];
	    }
	}

	export class KernelControllerState {
	    running: boolean;
	    profile: string;
	    url: string;
	    require_auth: boolean;
	    write: boolean;
	
	    static createFrom(source: any = {}) {
	        return new KernelControllerState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.profile = source["profile"];
	        this.url = source["url"];
	        this.require_auth = source["require_auth"];
	        this.write = source["write"];
	    }
	}

	export class KernelProfileState {
	    active: string;
	    profiles: string[];
	
	    static createFrom(source: any = {}) {
	        return new KernelProfileState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.active = source["active"];
	        this.profiles = source["profiles"];
	    }
	}

	export class KernelProfileRevision {
	    id: string;
	    created_at: string;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new KernelProfileRevision(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.created_at = source["created_at"];
	        this.bytes = source["bytes"];
	    }
	}

	export class KernelValidationResult {
	    valid: boolean;
	    message: string;
	    outbounds: number;
	    rules: number;
	    default_target: string;
	
	    static createFrom(source: any = {}) {
	        return new KernelValidationResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.valid = source["valid"];
	        this.message = source["message"];
	        this.outbounds = source["outbounds"];
	        this.rules = source["rules"];
	        this.default_target = source["default_target"];
	    }
	}

	export class KernelRouteTraceItem {
	    index: number;
	    rule: string;
	    outbound: string;
	    matched: boolean;
	
	    static createFrom(source: any = {}) {
	        return new KernelRouteTraceItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.rule = source["rule"];
	        this.outbound = source["outbound"];
	        this.matched = source["matched"];
	    }
	}

	export class KernelRouteProbeResult {
	    ok: boolean;
	    message: string;
	    matched: boolean;
	    rule: string;
	    outbound: string;
	    adapter_type: string;
	    trace: KernelRouteTraceItem[];
	
	    static createFrom(source: any = {}) {
	        return new KernelRouteProbeResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ok = source["ok"];
	        this.message = source["message"];
	        this.matched = source["matched"];
	        this.rule = source["rule"];
	        this.outbound = source["outbound"];
	        this.adapter_type = source["adapter_type"];
	        this.trace = source["trace"] ? source["trace"].map((item: any) => KernelRouteTraceItem.createFrom(item)) : [];
	    }
	}

	export class KernelRuntimeStats {
	    profile: string;
	    version: number;
	    total_routes: number;
	    matched_routes: number;
	    default_routes: number;
	    last_rule: string;
	    last_outbound: string;
	    outbound_hits: {[key: string]: number};
	    adapter_health: {[key: string]: string};
	
	    static createFrom(source: any = {}) {
	        return new KernelRuntimeStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile = source["profile"];
	        this.version = source["version"];
	        this.total_routes = source["total_routes"];
	        this.matched_routes = source["matched_routes"];
	        this.default_routes = source["default_routes"];
	        this.last_rule = source["last_rule"];
	        this.last_outbound = source["last_outbound"];
	        this.outbound_hits = source["outbound_hits"];
	        this.adapter_health = source["adapter_health"];
	    }
	}

}

