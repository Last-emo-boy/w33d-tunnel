export namespace main {
	
	export class Config {
	    sub_url: string;
	    socks_addr: string;
	    global_proxy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sub_url = source["sub_url"];
	        this.socks_addr = source["socks_addr"];
	        this.global_proxy = source["global_proxy"];
	    }
	}

}

