#!/usr/bin/env python
import frida
import sys
import pydwarfdb as dwarfparse
import json
import os

pid = None

def main():
	global pid

	retro = False
	rebirth = False
	chocolate = False
	if len(sys.argv) > 1 and len(sys.argv[1]) > 1: # a proper exe
		exe = sys.argv[1]
		if 'retro' in exe.lower():
			retro = True
		elif 'choco' in exe.lower():
			chocolate = True
		elif 'rebirth' in exe.lower():
			rebirth = True
		else:
			print('Could not determine source port from exe filename ' + exe)
			return
	else: # hacky shortcuts
		rebirth = len(sys.argv) > 1 and sys.argv[1] == '1'
		chocolate = len(sys.argv) > 1 and sys.argv[1] == '2'
		if chocolate:
			exe = "../../src/ChocolateDescent/build/ChocolateDescent"
		elif rebirth:
			exe = "../dxx-rebirth/build/d1x-rebirth/d1x-rebirth"
		else:
			exe = "../DXX-Retro-ar/lind1/d1x-rebirth"
		retro = not rebirth and not chocolate

	d1x = retro or rebirth

	sym = dwarfparse.SymbolManager()
	dwarfparse.DwarfParser.parseDwarfFromFilename(exe, sym)
	
	def membersOfs(t, members):
		ofs = 0
		m = None
		for x in members:
			while isinstance(t, dwarfparse.Typedef):
				t = t.getBaseType()
			#print(x)
			m = t.memberByName(x)
			ofs += m.getMemberLocation()
			#print(ofs)
			#print(isinstance(m, dwarfparse.StructuredMember))
			t = m.getBaseType()
			#print(repr(t))
			#print(t.getName())
		return ofs

	obj_t = sym.findBaseTypeByName(('object_base' if rebirth else 'object'))
	obj_x_t = None if retro else sym.findBaseTypeByName('object') 
	#print(repr(obj_t))
	#print('obj_x_t ' + repr(obj_x_t) + ' ' + str(obj_x_t.getByteSize()))
	obj_size = obj_t.getByteSize()
	if obj_x_t:
		obj_size = obj_x_t.getByteSize()
	obj_phys_flags = membersOfs(obj_t, ['mtype', 'phys_info', 'flags'])
	obj_pos = membersOfs(obj_t, ['pos'])
	obj_id = membersOfs(obj_t, ['id'])
	obj_track_goal = membersOfs(obj_x_t or obj_t, ['ctype', 'laser_info', 'track_goal'])
	#return
	#pl_t = sym.findBaseTypeByName('player_info')
	#pl_sec_ammo = pl_t.memberByName('secondary_ammo').getMemberLocation()
	obj_pl_sec_ammo = membersOfs(obj_x_t, ['ctype', 'player_info', 'secondary_ammo']) if rebirth else None
	obj_pl_sec_wpn = membersOfs(obj_x_t, ['ctype', 'player_info', 'Secondary_weapon']) if rebirth else None
	sh_rob_info = sym.findBaseTypeByName('d_level_shared_robot_info_state').memberByName('Robot_info').getMemberLocation() if rebirth else None

	def fun_addr(name):
		f = sym.findFunctionByName(name)
		if not f:
			raise Exception('fun not found: ' + name)
		a = f.getAddress()
		if not a:
			raise Exception('error getting address: ' + name)
		return a

	def var_addr(name):
		v = sym.findVariableByName(name)
		if not v:
			raise Exception('var not found: ' + name)
		return v.getLocation()

	exe_args = [exe, '-notitles', '-pilot', 'arne', '-nosound', '-nomusic']
	if chocolate:
		os.chdir(os.environ['HOME'] + '/.d1x-rebirth/data')
	pid = frida.spawn(exe, exe_args, stdio='pipe')
	#print('pid %d' % pid)
	with open('/proc/%d/maps' % pid, 'r') as f:
		for line in f.readlines():
			fields = line.split()
			base = int(fields[0].split('-')[0], 16)
			break
	def to_addrs(xs):
		return {x:str(base + fun_addr(x)) for x in xs}
	def v_to_addrs(xs):
		return {x:str(base + var_addr(x)) for x in xs}

	vals = {'obj_size':obj_size, 'obj_pl_sec_ammo':obj_pl_sec_ammo,
		'obj_pl_sec_wpn':obj_pl_sec_wpn,
		'obj_pos':obj_pos, 'obj_id':obj_id, 'obj_track_goal':obj_track_goal,
		'obj_phys_flags':obj_phys_flags,
		'rebirth':rebirth, 'd1x':d1x, 'retro':retro,
		'sh_rob_info':sh_rob_info}
	#print(repr(vals))

	session = frida.attach(pid)
	script = session.create_script("""
	var addrs = %s, vals = %s;
	var ptrs = {}
	for (var x in addrs)
		ptrs[x] = ptr(addrs[x]);
	//console.log(JSON.stringify(addrs));
	if (0)
	Interceptor.attach(ptrs.calc_frame_time, {
		onLeave(ret) {
			//send('calc_frame_time ' + 65536 / ptr(addrs.FrameTime).readInt());
			send('FrameTime ' + ptrs.FrameTime.readInt());
		}
	});
	function readVec(p) {
		return [p.readInt() / 65536, p.add(4).readInt() / 65536, p.add(8).readInt() / 65536];
	}
	function dist(a, b) {
		var dx = a[0] - b[0], dy = a[1] - b[1], dz = a[2] - b[2];
		return Math.sqrt(dx * dx + dy * dy + dz * dz);
	}
	function dot(a, b) {
		return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
	}
	function calcdir(a, b) {
		var dx = b[0] - a[0], dy = b[1] - a[1], dz = b[2] - a[2];
		var mag = Math.sqrt(dx * dx + dy * dy + dz * dz);
		return [dx / mag, dy / mag, dz / mag];
	}
	var the_missile;
	var last_pos, last_time, last_dir;
	Interceptor.attach(ptr(addrs.Laser_do_weapon_sequence), {
		onEnter(args) {
			var time = (vals.d1x ? ptr(addrs.GameTime64).readU64() : ptr(addrs.GameTime).readU32()) / 65536;
			var obj = vals.rebirth ? args[1] : args[0];
			the_missile = obj.sub(ptr(addrs.ConsoleObject).readPointer()) / vals.obj_size;
			var pos = readVec(obj.add(vals.obj_pos))
			var vel = 0, dir = null, ang = 0;
			if (last_pos) {
				vel = dist(last_pos, pos) / (time - last_time);
				dir = calcdir(last_pos, pos);
				if (last_dir) {
					var x = Math.max(-1, Math.min(1, dot(last_dir, dir)));
					ang = Math.acos(x) * 180 / Math.PI; // / (time - last_time);
				}
			}
			last_dir = dir;
			last_pos = pos;
			last_time = time;
			send([time].concat(pos).concat([vel, ang]).map(x => x.toFixed(5)).join(','));
			/*
			time.toFixed(5) + ',' +
				//' Laser_do_weapon_sequence ' + the_missile + ' ' +
				pos.map(x => x.toFixed(5)) + ',' + vel + ',' + ang) //+ ',' +
				//(ptrs.doHomerFrame ? ptrs.doHomerFrame.readInt() : 0));
				//obj.add(vals.obj_track_goal).readU16());
			*/
		}
	});
	if (0)
	Interceptor.attach(ptr(addrs.find_homing_object_complete), {
		onEnter(args) {
			send('find_homing_object_complete ' + args[2].toInt32() + ' ' + args[3].toInt32() + ' ' + args[4].toInt32());
		}
	});
	Interceptor.attach(ptr(addrs.obj_delete), {
		onEnter(args) {
			var obj = vals.rebirth ? args[2].sub(ptr(addrs.ConsoleObject).readPointer()) / vals.obj_size : args[0].toInt32();
			if (obj == the_missile)
				send('exit')
			//send('deleted ' + obj);
		}
	});
	var fixed_fps = 30;
	var fixed_frametime = Math.floor(65536 / fixed_fps);
	var time = 0;
	if(vals.d1x) {
		Interceptor.replace(ptrs.timer_update, new NativeCallback(() => {
			var F64_RunTime = ptrs.F64_RunTime;
			F64_RunTime.writeS64(time); //F64_RunTime.readS64() + 65536 / 200);
			return time;
		}, 'int64', []));
		// called on first frame
		Interceptor.attach(ptrs.timer_delay_ms || ptrs.timer_delay, {
			onLeave(retval) {
				time += fixed_frametime;
			}
		});
	} else {
		Interceptor.replace(ptrs.timer_get_fixed_seconds, new NativeCallback(() => {
			return time;
		}, 'int', []));
	}
	Interceptor.attach(ptrs.game_render_frame, {
		onLeave(retval) {
			time += fixed_frametime;
		}
	});
	Interceptor.replace(ptr(addrs.do_briefing_screens), new NativeCallback(() => {
	}, 'void', ['pointer', 'int']));
	Interceptor.replace(ptr(addrs.RegisterPlayer), new NativeCallback(() => {
		return 1;
	}, 'int', []));
	if (ptrs.gr_palette_fade_out)
		Interceptor.replace(ptrs.gr_palette_fade_out, new NativeCallback(() => {
		}, 'void', ['pointer', 'int', 'int']));
	if (ptrs.I_Delay) {
		Interceptor.replace(ptrs.I_Delay, new NativeCallback(() => {
			time += fixed_frametime;
		}, 'void', ['int']));
		Interceptor.replace(ptrs.I_DelayUS, new NativeCallback(() => {
			//time += fixed_frametime;
		}, 'void', ['uint64']));
		Interceptor.replace(ptrs.I_GetMS, new NativeCallback(() => {
			return time * 1000 / 65536;
		}, 'uint32', []));
		Interceptor.replace(ptrs.I_GetUS, new NativeCallback(() => {
			return time * 1e6 / 65536;
		}, 'uint64', []));
		Interceptor.replace(ptrs.I_GetTicks, new NativeCallback(() => {
			return Math.floor(time * 1000 / 65536) * 18 / 1000;
		}, 'uint32', []));
		Interceptor.replace(ptrs.I_MarkEnd, new NativeCallback(() => {
		}, 'void', ['uint64']));
	}
	var menu_seen;
	Interceptor.replace(ptr(addrs.DoMenu), new NativeCallback(() => {
		if (menu_seen && !vals.d1x) {
			ptr(addrs.Function_mode).writeInt(0); // FMODE_EXIT
			return 0;
		}
		menu_seen = 1;
		//send('menu'); //args[0].toInt32()
		var load_mission_by_name = new NativeFunction(ptr(addrs.load_mission_by_name), 'pointer', ['pointer', 'int']);
		var ret = load_mission_by_name(Memory.allocUtf8String(""), 0);
		if (vals.rebirth && !ret.isNull()) {
			send('load_mission failed ' + ret.readCString())
			return 0;
		}
		if (1) {
			var StartNewGame = new NativeFunction(ptr(addrs.StartNewGame), 'void', ['int']);
			StartNewGame(1);
		} else
		if (vals.rebirth) {
			var robInfo = ptr(addrs.LevelSharedRobotInfoState).add(vals.sh_rob_info);
			var StartNewLevelSub = new NativeFunction(ptr(addrs.StartNewLevelSub), 'int', ['pointer', 'int', 'int', 'int']);
			StartNewLevelSub(robInfo, 1, 1, 0);
		} else {
			var StartNewLevelSub = new NativeFunction(ptr(addrs.StartNewLevelSub), 'void', ['uint32', 'uint32']);
			StartNewLevelSub(1, 1);
		}
		//var obj_create = new NativeFunction(ptr(addrs.obj_create), 'int',
		//	['int', 'int', 'int', 'pointer', 'pointer', 'int', 'int', 'int', 'int'])
		//obj_create(4, 1, 0, ptr(), ptr(), 0x10000, 0, 0, 0);
		if (addrs.net_missile_firing) {
			if (vals.d1x) {
				var net_missile_firing = new NativeFunction(ptr(addrs.net_missile_firing), 'int',
					['int', 'int', 'int', 'int', 'int', 'int']);
				net_missile_firing(0, 7, 0, 0, 0x10000, 0);
			} else {
				var net_missile_firing = new NativeFunction(ptr(addrs.net_missile_firing), 'int',
					['int', 'int', 'int']);
				net_missile_firing(0, 7, 0);
			}
		} else {
			var hammo = ptr(addrs.ConsoleObject).readPointer().add(vals.obj_pl_sec_ammo + 1);
			hammo.writeU8(hammo.readU8() + 2);
			ptr(addrs.ConsoleObject).readPointer().add(vals.obj_pl_sec_wpn).writeU8(1);
			var do_missile_firing = new NativeFunction(ptr(addrs.do_missile_firing), 'void',
				['int', 'pointer', 'int']);
			do_missile_firing(1, ptr(addrs.ConsoleObject).readPointer(), 0);
		}
		var pl_phys_flags = ptr(addrs.ConsoleObject).readPointer().add(vals.obj_phys_flags);
		pl_phys_flags.writeU16(pl_phys_flags.readU16() & ~8); // disable wiggle
		//Memory.protect(pl_phys_flags, 2, '---');
		var Game_suspended = ptr(addrs.Game_suspended);
		Game_suspended.writeInt(Game_suspended.readInt() | 1); // suspend robots
		if (vals.retro)
			new NativeFunction(ptrs.set_homing_update_rate, 'void', ['int'])(30);
		if (ptrs.FPSLimit)
			ptrs.FPSLimit.writeInt(999); // disable to use our own fps
		return 0; //2; // close
	}, 'int', []));
	""" % (json.dumps({**to_addrs(['DoMenu', 'do_new_game_menu',
		'do_missile_firing', 'find_homing_object_complete',
		'do_briefing_screens', 'RegisterPlayer',
		'load_mission_by_name', 'StartNewLevelSub', 'StartNewGame',
		'calc_frame_time', 'obj_create', 'Laser_do_weapon_sequence', 
		'obj_delete', 'game_render_frame'] +
		(['gr_palette_fade_out', 'timer_get_fixed_seconds'] if not d1x else []) +
		(['I_Delay', 'I_DelayUS', 'I_GetMS', 'I_GetUS', 'I_GetTicks', 'I_MarkEnd'] if chocolate else []) +
		(['net_missile_firing'] if not rebirth else []) +
		(['set_homing_update_rate'] if retro else []) +
		(['timer_delay_ms'] if rebirth else []) +
		(['timer_update', 'timer_delay'] if d1x else [])),
		**v_to_addrs(['FrameTime', 'Objects', 'Game_suspended', 
			'ConsoleObject'] +
			(['d_tick_count', 'F64_RunTime', 'GameTime64'] if d1x else ['GameTime']) +
			(['GameTime', 'Function_mode'] if not d1x else []) +
			(['LevelSharedRobotInfoState'] if rebirth else []) +
			(['FPSLimit'] if chocolate else []) +
			(['doHomerFrame'] if retro else [])
			)}),
			
		json.dumps(vals)))
	script.on('message', on_message)
	script.load()

	#sys.stdin.readline()
	frida.resume(pid)
	#session.detach()
	
	sys.stdin.readline()

def on_message(message, data):
	global pid
	if message['type'] == 'send' and message['payload'] == 'exit':
		frida.kill(pid)
		sys.stdout.flush()
		os._exit(0)
		return
	if message['type'] == 'send':
		print(message['payload'])
	else:
		print(message)

main()
